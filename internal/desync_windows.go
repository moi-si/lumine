//go:build windows

package lumine

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

const minInterval = 100 * time.Millisecond

func minReachableTTL(addr string, ipv6 bool, maxTTL, attempts int, dialTimeout time.Duration) (int, bool, error) {
	if ttlCacheEnabled {
		if ttl, ok := ttlCache.Get(addr); ok {
			return ttl, true, nil
		}
	}

	var level, opt int
	if ipv6 {
		level, opt = windows.IPPROTO_IPV6, windows.IPV6_UNICAST_HOPS
	} else {
		level, opt = windows.IPPROTO_IP, windows.IP_TTL
	}
	dialer := net.Dialer{Timeout: dialTimeout}

	low, high := 1, maxTTL
	found := -1

	for low <= high {
		mid := (low + high) / 2
		dialer.Control = func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				sockErr = windows.SetsockoptInt(windows.Handle(fd), level, opt, mid)
			})
			if err != nil {
				return wrap("control", err)
			}
			return sockErr
		}
		var ok bool
		for range attempts {
			conn, err := dialer.Dial("tcp", addr)
			if err == nil {
				conn.Close()
				ok = true
				break
			}
		}
		if ok {
			found = mid
			high = mid - 1
		} else {
			low = mid + 1
		}
	}

	if ttlCacheEnabled && found != -1 {
		ttlCache.AddWithLifetime(addr, found, dnsCacheTTL)
	}

	return found, false, nil
}

func sendFakeData(
	sockHandle windows.Handle,
	fakeData, realData []byte,
	fakeLen, fakeTTL, defaultTTL, level, opt int,
	fakeSleep time.Duration,
) error {
	toWrite := uint32(fakeLen)

	tmpFile := filepath.Join(os.TempDir(), uuid.New().String())
	defer os.Remove(tmpFile)
	ptr, err := windows.UTF16PtrFromString(tmpFile)
	if err != nil {
		return err
	}
	fileHandle, err := windows.CreateFile(
		ptr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.CREATE_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_DELETE_ON_CLOSE,
		windows.InvalidHandle,
	)
	defer windows.CloseHandle(fileHandle)
	if err != nil {
		return wrap("create file", err)
	}

	var ov windows.Overlapped
	eventHandle, err := windows.CreateEvent(nil, 1, 0, nil)
	defer windows.CloseHandle(eventHandle)
	if err != nil {
		return wrap("create event", err)
	}
	ov.HEvent = eventHandle

	var zero *int32
	_, err = windows.SetFilePointer(fileHandle, 0, zero, 0)
	if err != nil {
		return wrap("set file pointer", err)
	}
	err = windows.WriteFile(
		fileHandle,
		fakeData,
		nil,
		&ov,
	)
	if err != nil {
		return wrap("write fake data", err)
	}
	if err = windows.SetEndOfFile(fileHandle); err != nil {
		return wrap("set end of file", err)
	}
	err = windows.SetsockoptInt(sockHandle, level, opt, fakeTTL)
	if err != nil {
		return wrap("set fake TTL", err)
	}

	_, err = windows.SetFilePointer(fileHandle, 0, zero, 0)
	if err != nil {
		return wrap("set file pointer", err)
	}
	if sem != nil {
		sem <- struct{}{}
		defer func() { <-sem }()
	}
	windows.TransmitFile(
		sockHandle,
		fileHandle,
		toWrite,
		toWrite,
		&ov,
		nil,
		windows.TF_USE_KERNEL_APC|windows.TF_WRITE_BEHIND,
	)
	time.Sleep(fakeSleep)

	if _, err = windows.SetFilePointer(fileHandle, 0, zero, 0); err != nil {
		return wrap("set file pointer", err)
	}
	err = windows.WriteFile(
		fileHandle,
		realData, // will be automatically sent by the system.
		nil,
		&ov,
	)
	if err != nil {
		return wrap("write real data to temp", err)
	}
	if err = windows.SetEndOfFile(fileHandle); err != nil {
		return wrap("set end of file", err)
	}
	_, err = windows.SetFilePointer(fileHandle, 0, zero, 0)
	if err != nil {
		return wrap("set file pointer", err)
	}
	if err = windows.SetsockoptInt(sockHandle, level, opt, defaultTTL); err != nil {
		return wrap("set default TTL", err)
	}

	val, err := windows.WaitForSingleObject(ov.HEvent, 5000)
	if err != nil {
		return wrap("TransmitFile call failed on waiting for event", err)
	}
	if val != 0 {
		return errors.New("TransmitFile call failed, val=" + strconv.FormatUint(uint64(val), 10))
	}
	return nil
}

func desyncSend(
	conn net.Conn, ipv6 bool,
	firstPacket []byte, sniPos, sniLen, fakeTTL int, fakeSleep time.Duration,
) error {
	rawConn, err := getRawConn(conn)
	if err != nil {
		return wrap("get raw conn", err)
	}
	var sockHandle windows.Handle
	controlErr := rawConn.Control(func(fd uintptr) {
		sockHandle = windows.Handle(fd)
	})
	if controlErr != nil {
		return wrap("control", err)
	}

	var level, opt int
	if ipv6 {
		level = windows.IPPROTO_IPV6
		opt = windows.IPV6_UNICAST_HOPS
	} else {
		level = windows.IPPROTO_IP
		opt = windows.IP_TTL
	}
	defaultTTL, err := windows.GetsockoptInt(sockHandle, level, opt)
	if err != nil {
		return wrap("get default TTL", err)
	}

	if fakeSleep < minInterval {
		fakeSleep = minInterval
	}

	cut, found := findLastDot(firstPacket, sniPos, sniLen)
	var fakeData []byte
	if found {
		fakeData = make([]byte, cut)
		copy(fakeData, firstPacket[:sniPos])
	} else {
		cut = sniLen/2 + sniPos
		fakeData = firstPacket[:cut]
	}

	err = sendFakeData(
		sockHandle,
		fakeData,
		firstPacket[:cut],
		cut,
		fakeTTL,
		defaultTTL,
		level, opt,
		fakeSleep,
	)
	if err != nil {
		return wrap("first sending", err)
	}
	/*err = sendFakeData(
		sockHandle,
		make([]byte, len(firstPacket)-cut),
		firstPacket[cut:],
		len(firstPacket)-cut,
		fakeTTL,
		defaultTTL,
		level, opt,
		fakeSleep,
	)*/
	if _, err = conn.Write(firstPacket[cut:]); err != nil {
		return wrap("second sending", err)
	}
	return nil
}

func sendWithOOB(conn net.Conn, b []byte) error {
	rawConn, err := getRawConn(conn)
	if err != nil {
		return wrap("get raw conn", err)
	}

	var sock windows.Handle
	controlErr := rawConn.Control(func(fd uintptr) {
		sock = windows.Handle(fd)
	})
	if controlErr != nil {
		return wrap("control", controlErr)
	}
	if sock == 0 {
		return errors.New("invalid socket handle")
	}

	data := make([]byte, len(b)+1)
	copy(data, b)
	data[len(b)] = '&'
	var (
		wsabuf    windows.WSABuf
		bytesSent uint32
	)
	wsabuf.Len = uint32(len(data))
	wsabuf.Buf = &data[0]

	err = windows.WSASend(
		sock,
		&wsabuf,
		1,
		&bytesSent,
		windows.MSG_OOB,
		nil,
		nil,
	)
	if err != nil {
		return wrap("WSASend", err)
	}
	if bytesSent != wsabuf.Len {
		return fmt.Errorf("WSASend: only %d of %d bytes sent", bytesSent, wsabuf.Len)
	}
	return nil
}

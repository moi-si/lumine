//go:build windows

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

func minReachableTTL(addr string, ipv6 bool, maxTTL, attempts int, dialTimeout time.Duration) (int, error) {
	if ttlCacheEnabled {
		v, ok := ttlCache.Load(addr)
		if ok {
			k := v.(ttlCacheEntry)
			if !k.ExpireAt.IsZero() {
				if time.Now().Before(k.ExpireAt) {
					return k.TTL, nil
				} else {
					ttlCache.Delete(addr)
				}
			}
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
				return fmt.Errorf("control: %w", err)
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
		var expireAt time.Time
		if ttlCacheTTL == -1 {
			expireAt = time.Time{}
		} else {
			expireAt = time.Now().Add(time.Duration(ttlCacheTTL * int(time.Second)))
		}
		ttlCache.Store(addr, ttlCacheEntry{
			TTL:      found,
			ExpireAt: expireAt,
		})
	}

	return found, nil
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
		return fmt.Errorf("create file: %v", err)
	}

	var ov windows.Overlapped
	eventHandle, err := windows.CreateEvent(nil, 1, 0, nil)
	defer windows.CloseHandle(eventHandle)
	if err != nil {
		return fmt.Errorf("create event: %v", err)
	}
	ov.HEvent = eventHandle

	var zero *int32
	_, err = windows.SetFilePointer(fileHandle, 0, zero, 0)
	if err != nil {
		return fmt.Errorf("set file pointer: %v", err)
	}
	err = windows.WriteFile(
		fileHandle,
		fakeData,
		nil,
		&ov,
	)
	if err != nil {
		return fmt.Errorf("write fake data: %v", err)
	}
	if err = windows.SetEndOfFile(fileHandle); err != nil {
		return fmt.Errorf("set end of file: %v", err)
	}
	err = windows.SetsockoptInt(sockHandle, level, opt, fakeTTL)
	if err != nil {
		return fmt.Errorf("set fake TTL: %v", err)
	}

	_, err = windows.SetFilePointer(fileHandle, 0, zero, 0)
	if err != nil {
		return fmt.Errorf("set file pointer: %v", err)
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
	time.Sleep(time.Duration(fakeSleep))

	if _, err = windows.SetFilePointer(fileHandle, 0, zero, 0); err != nil {
		return fmt.Errorf("set file pointer: %v", err)
	}
	err = windows.WriteFile(
		fileHandle,
		realData,
		nil,
		&ov,
	)
	if err != nil {
		return fmt.Errorf("write real data: %v", err)
	}
	if err = windows.SetEndOfFile(fileHandle); err != nil {
		return fmt.Errorf("set end of file: %v", err)
	}
	_, err = windows.SetFilePointer(fileHandle, 0, zero, 0)
	if err != nil {
		return fmt.Errorf("set file pointer: %v", err)
	}
	if err = windows.SetsockoptInt(sockHandle, level, opt, defaultTTL); err != nil {
		return fmt.Errorf("set default TTL: %v", err)
	}

	val, err := windows.WaitForSingleObject(ov.HEvent, 5000)
	if err != nil {
		return fmt.Errorf("TransmitFile call failed on waiting for event: %v", err)
	}
	if val != 0 {
		return errors.New("TransmitFile call failed")
	}
	return nil
}

func desyncSend(
	conn net.Conn, ipv6 bool,
	firstPacket []byte, sniPos, sniLen, fakeTTL int, fakeSleep time.Duration,
) error {
	rawConn, err := getRawConn(conn)
	if err != nil {
		return fmt.Errorf("get rawConn: %s", err)
	}
	var sockHandle windows.Handle
	controlErr := rawConn.Control(func(fd uintptr) {
		sockHandle = windows.Handle(fd)
	})
	if controlErr != nil {
		return fmt.Errorf("control: %s", err)
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
		return fmt.Errorf("get default TTL: %s", err)
	}

	if fakeSleep < minInterval {
		fakeSleep = minInterval
	}

	cut := -1
	for i := sniPos + sniLen; i >= sniPos; i-- {
		if firstPacket[i] == '.' {
			cut = i
			break
		}
	}
	var fakeData []byte
	if cut == -1 {
		cut = sniLen/2 + sniPos
		fakeData = firstPacket[:cut]
	} else {
		fakeData = make([]byte, cut)
		copy(fakeData, firstPacket[:sniPos])
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
		return fmt.Errorf("first sending: %s", err)
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
		return fmt.Errorf("second sending: %s", err)
	}
	return nil
}

func sendOOB(conn net.Conn) error {
	rawConn, err := getRawConn(conn)
	if err != nil {
		return fmt.Errorf("get raw conn: %s", err)
	}

	var sock windows.Handle
	controlErr := rawConn.Control(func(fd uintptr) {
		sock = windows.Handle(fd)
	})
	if controlErr != nil {
		return fmt.Errorf("control: %s", controlErr)
	}
	if sock == 0 {
		return fmt.Errorf("invalid socket handle")
	}

	var (
		wsabuf    windows.WSABuf
		data      byte = '&'
		bytesSent uint32
	)
	wsabuf.Len = 1
	wsabuf.Buf = &data

	err = windows.WSASend(
		sock,
		&wsabuf,
		1,               // dwBufferCount
		&bytesSent,      // lpNumberOfBytesSent
		windows.MSG_OOB, // dwFlags (MSG_OOB)
		nil,             // lpOverlapped
		nil,             // lpCompletionRoutine
	)
	if err != nil {
		return fmt.Errorf("WSASend: %s", err)
	}
	if bytesSent != wsabuf.Len {
		return fmt.Errorf("WSASend: only %d of %d bytes sent", bytesSent, wsabuf.Len)
	}
	return nil
}

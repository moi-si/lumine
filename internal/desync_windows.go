//go:build windows

package lumine

import (
	"io"
	"net"
	"os"
	"syscall"
	"time"

	E "github.com/moi-si/lumine/internal/errors"
	F "github.com/moi-si/lumine/internal/format"
	"golang.org/x/sys/windows"
)

const minInterval = 100 * time.Millisecond

func detectMinimalReachableTTL(
	addr string, ipv6 bool,
	maxTTL, attempts int,
	dialTimeout time.Duration,
) (int, error) {
	var level, opt int
	if ipv6 {
		level, opt = windows.IPPROTO_IPV6, windows.IPV6_UNICAST_HOPS
	} else {
		level, opt = windows.IPPROTO_IP, windows.IP_TTL
	}
	dialer := net.Dialer{Timeout: dialTimeout}

	low, high := 1, maxTTL
	found := unsetInt

	for low <= high {
		mid := (low + high) / 2
		dialer.Control = func(_, _ string, c syscall.RawConn) error {
			var innerErr error
			if err := c.Control(func(fd uintptr) {
				innerErr = windows.SetsockoptInt(windows.Handle(fd), level, opt, mid)
			}); err != nil {
				return E.WithStr("raw control", err)
			}
			if innerErr != nil {
				return E.WithStr("setsockopt", innerErr)
			}
			return nil
		}
		var ok bool
		for range attempts {
			conn, err := dialer.Dial("tcp", addr)
			if err == nil {
				conn.Close()
				ok = true
				break
			}
			if netErr := err.(*net.OpError); !netErr.Timeout() {
				return unsetInt, E.WithStr("dial "+F.Int(mid), err)
			}
		}
		if ok {
			found = mid
			high = mid - 1
		} else {
			low = mid + 1
		}
	}

	if ttlCache != nil && found != unsetInt {
		ttlCache.AddWithLifetime(addr, found, ttlCacheTTL)
	}
	return found, nil
}

func sendWithNoise(
	sockHandle windows.Handle,
	fakeData, realData []byte,
	fakeTTL, defaultTTL, level, opt int,
	fakeSleep time.Duration,
) error {
	realDataLen := len(realData)
	if len(fakeData) != realDataLen {
		return E.New("the length of realData must equal to that of fakeData")
	}

	tmpFile, err := os.CreateTemp("", "")
	if err != nil {
		return E.WithStr("create temp file", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err = tmpFile.Seek(0, io.SeekStart); err != nil {
		return E.WithStr("seek start", err)
	}

	_, err = tmpFile.Write(fakeData)
	if err != nil {
		return E.WithStr("write fake data", err)
	}

	if err = tmpFile.Sync(); err != nil {
		return E.WithStr("sync fake data", err)
	}

	if err = windows.SetsockoptInt(
		sockHandle, level, opt, fakeTTL,
	); err != nil {
		return E.WithStr("set fake TTL", err)
	}

	if _, err = tmpFile.Seek(0, io.SeekStart); err != nil {
		return E.WithStr("seek start", err)
	}

	var ov windows.Overlapped
	ov.HEvent, err = windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return E.WithStr("create event", err)
	}
	defer windows.CloseHandle(ov.HEvent)

	if sem != nil {
		sem <- struct{}{}
		defer func() { <-sem }()
	}

	rawConn, err := tmpFile.SyscallConn()
	if err != nil {
		return E.WithStr("get raw conn", err)
	}
	var transmitFileErr error
	rawCtrlErr := rawConn.Control(func(fd uintptr) {
		toWrite := uint32(realDataLen)
		transmitFileErr = windows.TransmitFile(
			sockHandle,
			windows.Handle(fd),
			toWrite,
			toWrite,
			&ov,
			nil,
			windows.TF_USE_KERNEL_APC|windows.TF_WRITE_BEHIND,
		)
	})
	if rawCtrlErr != nil {
		return E.WithStr("raw control", rawCtrlErr)
	}
	if transmitFileErr != nil && transmitFileErr != windows.ERROR_IO_PENDING {
		return E.WithStr("call TransmitFile", err)
	}

	time.Sleep(fakeSleep)

	if _, err = tmpFile.Seek(0, io.SeekStart); err != nil {
		return E.WithStr("seek start", err)
	}

	_, err = tmpFile.Write(realData)
	if err != nil {
		return E.WithStr("write real data", err)
	}

	if err = tmpFile.Sync(); err != nil {
		return E.WithStr("sync real data", err)
	}

	if _, err = tmpFile.Seek(0, io.SeekStart); err != nil {
		return E.WithStr("seek start", err)
	}
	if err = windows.SetsockoptInt(
		sockHandle, level, opt, defaultTTL,
	); err != nil {
		return E.WithStr("set default TTL", err)
	}

	event, err := windows.WaitForSingleObject(ov.HEvent, 5000)
	if err != nil {
		return E.WithStr("wait for TransmitFile", err)
	}

	switch event {
	case windows.WAIT_OBJECT_0:
	case uint32(windows.WAIT_TIMEOUT):
		return E.New("wait for TransmitFile: timeout (5s)")
	case windows.WAIT_ABANDONED:
		return E.New("wait for TransmitFile: WAIT_ABANDONED")
	case windows.WAIT_FAILED:
		return E.WithStr("wait for TransmitFile: WAIT_FAILED", windows.GetLastError())
	default:
		return E.New("wait for TransmitFile: unexpected event: " + F.Uint(event))
	}

	var n, flags uint32
	if err = windows.WSAGetOverlappedResult(
		sockHandle, &ov, &n, false, &flags,
	); err != nil {
		return E.WithStr("get TransmitFile result", err)
	}
	if int(n) < realDataLen {
		return E.New(F.Concat("sent only ", n, " of ", realDataLen, " bytes"))
	}
	return nil
}

func desyncSend(
	conn net.Conn, ipv6 bool,
	record []byte, sniStart, sniLen, fakeTTL int, fakeSleep time.Duration,
) error {
	rawConn, err := getTCPRawConn(conn)
	if err != nil {
		return err
	}

	var sockHandle windows.Handle
	controlErr := rawConn.Control(func(fd uintptr) {
		sockHandle = windows.Handle(fd)
	})
	if controlErr != nil {
		return E.WithStr("raw control", err)
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
		return E.WithStr("get default TTL", err)
	}

	if fakeSleep < minInterval {
		fakeSleep = minInterval
	}

	cut := findLastDotOrMidPos(record, sniStart, sniLen)
	fakeData := make([]byte, cut)
	copy(fakeData, record[:sniStart])

	if err = sendWithNoise(
		sockHandle,
		fakeData, record[:cut],
		fakeTTL, defaultTTL,
		level, opt,
		fakeSleep,
	); err != nil {
		return E.WithStr("send data with noise", err)
	}
	if _, err = conn.Write(record[cut:]); err != nil {
		return E.WithStr("send remaining data", err)
	}
	return nil
}

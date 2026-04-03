//go:build linux

package lumine

import (
	"errors"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const minInterval = 100 * time.Millisecond

func detectMinimalReachableTTL(
	addr string, ipv6 bool,
	maxTTL, attempts int,
	dialTimeout time.Duration,
) (int, error) {
	var level, opt int
	if ipv6 {
		level, opt = unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS
	} else {
		level, opt = unix.IPPROTO_IP, unix.IP_TTL
	}
	dialer := net.Dialer{Timeout: dialTimeout}

	low, high := 1, maxTTL
	found := -1

	for low <= high {
		mid := (low + high) / 2
		dialer.Control = func(_, _ string, c syscall.RawConn) error {
			var innerErr error
			if err := c.Control(func(fd uintptr) {
				innerErr = unix.SetsockoptInt(
					int(fd),
					level,
					opt,
					mid,
				)
			}); err != nil {
				return wrap("raw control", err)
			}
			if innerErr != nil {
				return wrap("setsockopt", innerErr)
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
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				return -1, wrap("dial "+formatInt(mid), err)
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
		ttlCache.AddWithLifetime(addr, found, ttlCacheTTL)
	}
	return found, nil
}

func sendWithNoise(
	socketFD int, rawConn syscall.RawConn,
	fakeData, realData []byte,
	fakeTTL, defaultTTL, level, opt int,
	fakeSleep time.Duration,
) error {
	var pipeFDs [2]int
	if err := unix.Pipe2(pipeFDs[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		return wrap("create pipe", err)
	}
	pipeR, pipeW := pipeFDs[0], pipeFDs[1]
	defer unix.Close(pipeR)
	defer unix.Close(pipeW)

	pageSize := syscall.Getpagesize()
	nPages := (len(fakeData) + pageSize - 1) / pageSize
	mmapLen := nPages * pageSize
	data, err := unix.Mmap(-1, 0, mmapLen,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return wrap("mmap", err)
	}
	defer unix.Munmap(data)
	copy(data, fakeData)

	err = unix.SetsockoptInt(socketFD, level, opt, fakeTTL)
	if err != nil {
		return wrap("set fake TTL", err)
	}
	iov := unix.Iovec{
		Base: &data[0],
		Len:  toUint(len(fakeData)),
	}
	if _, err := unix.Vmsplice(pipeW, []unix.Iovec{iov}, unix.SPLICE_F_GIFT); err != nil {
		return wrap("vmsplice", err)
	}

	errChan, innerErrChan := make(chan error), make(chan error)
	go func() {
		var innerErr error
		err := rawConn.Write(func(fd uintptr) (done bool) {
			for {
				_, innerErr = unix.Splice(
					pipeR,
					nil,
					int(fd),
					nil,
					len(fakeData),
					unix.SPLICE_F_NONBLOCK,
				)
				if innerErr == unix.EINTR {
					continue
				}
				return innerErr != unix.EAGAIN
			}
		})
		errChan <- err
		innerErrChan <- innerErr
	}()

	time.Sleep(fakeSleep)

	copy(data, realData) // will be sent automatically by the system.

	err = unix.SetsockoptInt(socketFD, level, opt, defaultTTL)
	if err != nil {
		return wrap("set default TTL", err)
	}
	err = <-errChan
	innerErr := <-innerErrChan
	if err != nil {
		return wrap("raw write (splice)", err)
	}
	if innerErr != nil {
		return wrap("splice", innerErr)
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

	var fd int
	err = rawConn.Control(func(fileDesc uintptr) {
		fd = int(fileDesc)
	})
	if err != nil {
		return wrap("raw control", err)
	}

	var level, opt, defaultTTL int
	if ipv6 {
		level = unix.IPPROTO_IPV6
		opt = unix.IPV6_UNICAST_HOPS
	} else {
		level = unix.IPPROTO_IP
		opt = unix.IP_TTL
	}
	defaultTTL, err = unix.GetsockoptInt(fd, level, opt)
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
		fakeData = firstPacket[:cut]
	}

	if err = sendWithNoise(
		fd, rawConn,
		fakeData,
		firstPacket[:cut],
		fakeTTL,
		defaultTTL,
		level, opt,
		fakeSleep,
	); err != nil {
		return wrap("send data with noise", err)
	}
	if _, err = conn.Write(firstPacket[cut:]); err != nil {
		return wrap("send remaining data", err)
	}
	return nil
}

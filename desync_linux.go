//go:build linux

package main

import (
	"errors"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
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
			var sockErr error
			err := c.Control(func(fd uintptr) {
				sockErr = unix.SetsockoptInt(int(fd), level, opt, mid)
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
	fd int,
	fakeData, realData []byte,
	fakeTTL, defaultTTL, level, opt int,
	fakeSleep time.Duration,
) error {
	pipeFds := make([]int, 2)
	if err := unix.Pipe(pipeFds); err != nil {
		return wrap("pipe creation", err)
	}
	pipeR, pipeW := pipeFds[0], pipeFds[1]
	defer unix.Close(pipeR)
	defer unix.Close(pipeW)

	pageSize := unix.Getpagesize()
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

	err = unix.SetsockoptInt(int(fd), level, opt, fakeTTL)
	if err != nil {
		return wrap("set fake ttl", err)
	}
	iov := unix.Iovec{
		Base: &data[0],
		Len:  toUint(len(fakeData)),
	}
	if _, err := unix.Vmsplice(pipeW, []unix.Iovec{iov}, unix.SPLICE_F_GIFT); err != nil {
		return wrap("vmsplice", err)
	}
	if _, err := unix.Splice(pipeR, nil, fd, nil, len(fakeData), 0); err != nil {
		return wrap("splice", err)
	}
	time.Sleep(fakeSleep)

	copy(data, realData) // will be automatically sent by the system.

	err = unix.SetsockoptInt(int(fd), level, opt, defaultTTL)
	if err != nil {
		return wrap("set default ttl", err)
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
		return wrap("control", err)
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
		return wrap("get default ttl", err)
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
		fd,
		fakeData,
		firstPacket[:cut],
		fakeTTL,
		defaultTTL,
		level, opt,
		fakeSleep,
	)
	if err != nil {
		return wrap("first sending", err)
	}
	/*err = sendFakeData(
		fd,
		make([]byte, len(firstPacket)-cut),
		firstPacket[cut:],
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

func sendOOB(conn net.Conn) error {
	rawConn, err := getRawConn(conn)
	if err != nil {
		return wrap("get raw conn", err)
	}

	var fd uintptr
	if ctrlErr := rawConn.Control(func(f uintptr) {
		fd = f
	}); ctrlErr != nil {
		return wrap("control", ctrlErr)
	}
	if fd == 0 {
		return errors.New("invalid socket descriptor")
	}
	if err = unix.Sendto(int(fd), []byte{'&'}, unix.MSG_OOB, nil); err != nil {
		return wrap("unix.Sendto (MSG_OOB)", err)
	}
	return nil
}

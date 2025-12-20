//go:build linux
// +build linux

package main

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"
	"sync"
	"errors"

	"golang.org/x/sys/unix"
)

func tryConnectWithTTL(target string, level, opt, ttl int) (bool, error) {
	dialer := net.Dialer{
		Timeout: 500 * time.Millisecond,
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				sockErr = unix.SetsockoptInt(int(fd),
					level,
					opt,
					ttl)
			})
			if err != nil {
				return err
			}
			return sockErr
		},
	}

	conn, err := dialer.DialContext(context.Background(), "tcp", target)
	if err != nil {
		return false, err
	}
	conn.Close()
	return true, nil
}

var ttlCache sync.Map

func minReachableTTL(addr string, ipv6 bool) (int, error) {
	v, ok := ttlCache.Load(addr)
	if ok {
		return v.(int), nil
	}
	var level, opt int
	if ipv6 {
		level, opt = unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS
	} else {
		level, opt = unix.IPPROTO_IP, unix.IP_TTL
	}
	low, high := 1, 32
	found := -1

	for low <= high {
		mid := (low + high) / 2
		ok, err := tryConnectWithTTL(addr, level, opt, mid)
		if err != nil {
			ok = false
		}
		if ok {
			found = mid
			high = mid - 1
		} else {
			low = mid + 1
		}
	}
	ttlCache.Store(addr, found)
	return found, nil
}

func sendFakeData(
	fd int, control func(func(fd uintptr)) error,
	fakeData, realData []byte,
	fakeTTL, defaultTTL, level, opt int,
	fakeSleep float64,
) error {
	pipeFds := make([]int, 2)
	if err := unix.Pipe(pipeFds); err != nil {
		return fmt.Errorf("pipe creation: %w", err)
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
		return fmt.Errorf("mmap: %w", err)
	}
	defer unix.Munmap(data)
	copy(data, fakeData)

	var setErr error
	err = control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), level, opt, fakeTTL)
	})
	if err != nil {
		return fmt.Errorf("control: %s", err)
	}
	if setErr != nil {
		return fmt.Errorf("set ttl: %s", err)
	}
	iov := unix.Iovec{
		Base: &data[0],
		Len:  uint64(len(fakeData)),
	}
	if _, err := unix.Vmsplice(pipeW, []unix.Iovec{iov}, unix.SPLICE_F_GIFT); err != nil {
		return fmt.Errorf("vmsplice: %s", err)
	}
	if _, err := unix.Splice(pipeR, nil, fd, nil, len(fakeData), 0); err != nil {
		return fmt.Errorf("splice: %s", err)
	}
	if fakeSleep < 0.1 {
		fakeSleep = 0.1
	}
	time.Sleep(time.Duration(fakeSleep * float64(time.Second)))

	copy(data, realData)

	err = control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), level, opt, defaultTTL)
	})
	if err != nil {
		return fmt.Errorf("control: %s", err)
	}
	return nil
}

func desyncSend(
	conn net.Conn, ipv6 bool,
	firstPacket, fakeData []byte, sniPos, sniLen, fakeTTL int, fakeSleep float64,
) error {
	rawConn, err := getRawConn(conn)
	if err != nil {
		return fmt.Errorf("get rawConn: %s", err)
	}
	var fd int
	err = rawConn.Control(func(fileDesc uintptr) {
		fd = int(fileDesc)
	})
	if err != nil {
		return fmt.Errorf("control: %w", err)
	}

	var (
		level, opt, defaultTTL int
		getErr                 error
	)
	if ipv6 {
		level = unix.IPPROTO_IPV6
		opt = unix.IPV6_UNICAST_HOPS
	} else {
		level = unix.IPPROTO_IP
		opt = unix.IP_TTL
	}
	err = rawConn.Control(func(fd uintptr) {
		defaultTTL, getErr = unix.GetsockoptInt(int(fd), level, opt)
	})
	if err != nil {
		return fmt.Errorf("control: %s", err)
	}
	if getErr != nil {
		return fmt.Errorf("get default ttl: %s", err)
	}

	fakeLen := len(fakeData)
	if len(firstPacket) < fakeLen {
		fakeData = []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
		fakeLen = len(fakeData)
		if len(firstPacket) < fakeLen {
			return errors.New("first packet too short")
		}
	}
	if fakeSleep < 0.1 {
		fakeSleep = 0.1
	}
	err = sendFakeData(fd, rawConn.Control,
		fakeData, firstPacket[:fakeLen],
		fakeTTL, defaultTTL, level, opt, fakeSleep)
	if err != nil {
		return fmt.Errorf("send fake data: %s", err)
	}
	firstPacket = firstPacket[fakeLen:]
	offset := sniLen/2 + sniPos - fakeLen
	if offset <= 0 {
		if _, err = conn.Write(firstPacket); err != nil {
			return fmt.Errorf("send remaining data: %s", err)
		}
		return nil
	}
	if _, err = conn.Write(firstPacket[:offset]); err != nil {
		return fmt.Errorf("send data after first faking: %s", err)
	}
	firstPacket = firstPacket[offset:]
	if len(firstPacket) < fakeLen {
		if _, err = conn.Write(firstPacket); err != nil {
			return fmt.Errorf("send remaining data: %s", err)
		}
		return nil
	}
	err = sendFakeData(fd, rawConn.Control,
		fakeData, firstPacket[:fakeLen],
		fakeTTL, defaultTTL, level, opt, fakeSleep)
	if err != nil {
		return fmt.Errorf("send fake data (2): %s", err)
	}
	if _, err = conn.Write(firstPacket[fakeLen:]); err != nil {
		return fmt.Errorf("send remaining data (2): %s", err)
	}
	return nil
}

func sendOOB(conn net.Conn, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	rawConn, err := getRawConn(conn)
	if err != nil {
		return fmt.Errorf("get raw conn: %w", err)
	}

	var fd uintptr
	if ctrlErr := rawConn.Control(func(f uintptr) {
		fd = f
	}); ctrlErr != nil {
		return fmt.Errorf("control: %w", ctrlErr)
	}
	if fd == 0 {
		return fmt.Errorf("invalid socket descriptor")
	}
	if err = unix.Sendto(int(fd), data, unix.MSG_OOB, nil); err != nil {
		return fmt.Errorf("unix.Sendto (MSG_OOB): %w", err)
	}
	return nil
}

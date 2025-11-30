//go:build linux
// +build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

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

func minReachableTTL(target string, ipv6 bool) (int, error) {
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
		ok, err := tryConnectWithTTL(target, level, opt, mid)
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
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return errors.New("not *net.TCPConn")
	}
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("get rawConn: %v", err)
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

	dataLen := len(fakeData)
	if fakeSleep < 0.1 {
		fakeSleep = 0.1
	}
	err = sendFakeData(fd, rawConn.Control,
		fakeData, firstPacket[:dataLen],
		fakeTTL, defaultTTL, level, opt, fakeSleep)
	if err != nil {
		return fmt.Errorf("send fake data: %s", err)
	}
	firstPacket = firstPacket[dataLen:]
	offset := sniLen/2 + sniPos - dataLen
	if offset <= 0 {
		if _, err = conn.Write(firstPacket); err != nil {
			return fmt.Errorf("send remaining data: %v", err)
		}
		return nil
	}
	if _, err = conn.Write(firstPacket[:offset]); err != nil {
		return fmt.Errorf("send data after first faking: %v", err)
	}
	firstPacket = firstPacket[offset:]
	err = sendFakeData(fd, rawConn.Control,
		fakeData, firstPacket[:dataLen],
		fakeTTL, defaultTTL, level, opt, fakeSleep)
	if err != nil {
		return fmt.Errorf("send fake data (2): %s", err)
	}
	if _, err = conn.Write(firstPacket[dataLen:]); err != nil {
		return fmt.Errorf("send remaining data: %s", err)
	}
	return nil
}

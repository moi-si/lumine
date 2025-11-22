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
	"unsafe"

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
	return 0, fmt.Errorf("Linux/Android is not supported yet")
	/*var level, opt int
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
	return found, nil*/
}

func sendFakeData(
	fd int,
	fakeData, realData []byte,
	dataLen, fakeTTL, defaultTTL, level, opt int,
	fakeSleep time.Duration,
) error {
	buf, err := unix.Mmap(
		0,
		0,
		(dataLen+3)&^3,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS,
	)
	if err != nil {
		return fmt.Errorf("mmap: %s", err)
	}
	defer unix.Munmap(buf)
	copy(buf[:dataLen], fakeData)
	if err = unix.SetsockoptInt(fd, level, opt, fakeTTL); err != nil {
		return fmt.Errorf("set fake ttl: %s", err)
	}
	pipeFds := make([]int, 2)
	if err = unix.Pipe(pipeFds); err != nil {
		return fmt.Errorf("create pipe: %s", err)
	}
	defer unix.Close(pipeFds[0])
	defer unix.Close(pipeFds[1])
	vec := unix.Iovec{Base: (*byte)(unsafe.Pointer(&buf[0]))}
	vec.SetLen(dataLen)
	if _, err = unix.Vmsplice(pipeFds[1], []unix.Iovec{vec}, unix.SPLICE_F_GIFT); err != nil {
		return fmt.Errorf("vmsplice: %s", err)
	}
	if _, err = unix.Splice(pipeFds[0], nil, pipeFds[1], nil, dataLen, 0); err != nil {
		return fmt.Errorf("splice: %s", err)
	}
	time.Sleep(fakeSleep)
	copy(buf[:dataLen], realData)
	if err = unix.SetsockoptInt(fd, level, opt, defaultTTL); err != nil {
		return fmt.Errorf("set default ttl: %s", err)
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
	if err := tcpConn.SetNoDelay(true); err != nil {
		return fmt.Errorf("set TCP_NODELAY: %v", err)
	}
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("get raw conn: %v", err)
	}
	var fd int
	controlErr := rawConn.Control(func(fileDesc uintptr) {
		fd = int(fileDesc)
	})
	if controlErr != nil {
		return fmt.Errorf("control: %v", err)
	}

	var level, opt int
	if ipv6 {
		level = unix.IPPROTO_IPV6
		opt = unix.IPV6_UNICAST_HOPS
	} else {
		level = unix.IPPROTO_IP
		opt = unix.IP_TTL
	}
	defaultTTL, err := unix.GetsockoptInt(fd, level, opt)
	if err != nil {
		return fmt.Errorf("get default ttl: %s", err)
	}
	dataLen := len(fakeData)
	sleepSec := time.Duration(fakeSleep * float64(time.Second))
	err = sendFakeData(
		fd,
		fakeData, firstPacket[:dataLen], dataLen,
		fakeTTL, defaultTTL,
		level, opt,
		sleepSec,
	)
	if err != nil {
		return fmt.Errorf("send first fake data: %s", err)
	}
	firstPacket = firstPacket[dataLen:]
	offset := sniLen/2 + sniPos - dataLen
	if offset <= 0 {
		if _, err = conn.Write(firstPacket); err != nil {
			return fmt.Errorf("send data after first fake packet: %s", err)
		}
		return nil
	}
	if _, err = conn.Write(firstPacket[:offset]); err != nil {
		return fmt.Errorf("send data after first fake packet: %s", err)
	}
	firstPacket = firstPacket[offset:]
	err = sendFakeData(
		fd,
		fakeData, firstPacket[:dataLen], dataLen,
		fakeTTL, defaultTTL,
		level, opt,
		sleepSec,
	)
	if err != nil {
		return fmt.Errorf("send second fake data: %s", err)
	}
	if _, err = conn.Write(firstPacket[dataLen:]); err != nil {
		return fmt.Errorf("send remaining data: %s", err)
	}
	return nil
}

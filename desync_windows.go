//go:build windows
// +build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

var ttlCache sync.Map

func minReachableTTL(addr string, ipv6 bool) (int, error) {
	v, ok := ttlCache.Load(addr)
	if ok {
		return v.(int), nil
	}
	var level, opt int
	if ipv6 {
		level, opt = windows.IPPROTO_IPV6, windows.IPV6_UNICAST_HOPS
	} else {
		level, opt = windows.IPPROTO_IP, windows.IP_TTL
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

func tryConnectWithTTL(address string, level, opt, ttl int) (bool, error) {
	dialer := net.Dialer{
		Timeout: 500 * time.Millisecond,
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				sockErr = windows.SetsockoptInt(windows.Handle(fd),
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

	conn, err := dialer.DialContext(context.Background(), "tcp", address)
	if err != nil {
		return false, err
	}
	conn.Close()
	return true, nil
}

func sendFakeData(
	sockHandle windows.Handle,
	fakeData, realData []byte,
	fakeLen, fakeTTL, defaultTTL, level, opt int,
	fakeSleep float64,
) error {
	if fakeSleep < 0.1 {
		fakeSleep = 0.1
	}
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
	time.Sleep(time.Duration(fakeSleep * float64(time.Second)))

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
	firstPacket, fakeData []byte, sniPos, sniLen, fakeTTL int, fakeSleep float64,
) error {
	rawConn, err := getRawConn(conn)
	if err != nil {
		return fmt.Errorf("get rawConn: %v", err)
	}
	var sockHandle windows.Handle
	controlErr := rawConn.Control(func(fd uintptr) {
		sockHandle = windows.Handle(fd)
	})
	if controlErr != nil {
		return fmt.Errorf("control: %v", err)
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
		return fmt.Errorf("get default TTL: %v", err)
	}
	fakeLen := len(fakeData)
	if len(firstPacket) < fakeLen {
		fakeData = []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
		fakeLen = len(fakeData)
		if len(firstPacket) < fakeLen {
			return errors.New("first packet too short")
		}
	}
	err = sendFakeData(
		sockHandle,
		fakeData,
		firstPacket[:fakeLen],
		fakeLen,
		fakeTTL,
		defaultTTL,
		level, opt,
		fakeSleep,
	)
	if err != nil {
		return fmt.Errorf("send first fake data: %v", err)
	}
	firstPacket = firstPacket[fakeLen:]
	offset := sniLen/2 + sniPos - fakeLen
	if offset <= 0 {
		if _, err = conn.Write(firstPacket); err != nil {
			return fmt.Errorf("send data after first fake packet: %v", err)
		}
		return nil
	}
	if _, err = conn.Write(firstPacket[:offset]); err != nil {
		return fmt.Errorf("send data after first fake packet: %v", err)
	}
	firstPacket = firstPacket[offset:]
	if len(firstPacket) < fakeLen {
		if _, err = conn.Write(firstPacket); err != nil {
			return fmt.Errorf("send remaining data: %s", err)
		}
		return nil
	}
	err = sendFakeData(
		sockHandle,
		fakeData,
		firstPacket[:fakeLen],
		fakeLen,
		fakeTTL,
		defaultTTL,
		level, opt,
		fakeSleep,
	)
	if err != nil {
		return fmt.Errorf("send second fake data: %v", err)
	}
	if _, err = conn.Write(firstPacket[fakeLen:]); err != nil {
		return fmt.Errorf("send remaining data: %v", err)
	}

	return nil
}

func sendOOB(conn net.Conn, data []byte) error {
	if len(data) == 0 {
		return nil // nothing to send
	}

	rawConn, err := getRawConn(conn)
	if err != nil {
		return fmt.Errorf("get raw conn: %w", err)
	}

	var sock windows.Handle
	controlErr := rawConn.Control(func(fd uintptr) {
		sock = windows.Handle(fd)
	})
	if controlErr != nil {
		return fmt.Errorf("control: %w", controlErr)
	}
	if sock == 0 {
		return fmt.Errorf("invalid socket handle")
	}

	var wsabuf windows.WSABuf
	wsabuf.Len = uint32(len(data))
	wsabuf.Buf = &data[0]

	var bytesSent uint32
	const dwFlags = windows.MSG_OOB

	err = windows.WSASend(
		sock,
		&wsabuf,
		1,          // dwBufferCount
		&bytesSent, // lpNumberOfBytesSent
		dwFlags,    // dwFlags (MSG_OOB)
		nil,        // lpOverlapped
		nil,        // lpCompletionRoutine
	)
	if err != nil {
		return fmt.Errorf("WSASend: %w", err)
	}
	if bytesSent != wsabuf.Len {
		return fmt.Errorf("WSASend: only %d of %d bytes sent", bytesSent, wsabuf.Len)
	}
	return nil
}

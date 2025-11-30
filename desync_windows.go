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
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

func minReachableTTL(addr string, ipv6 bool) (int, error) {
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
	dataLen, fakeTTL, defaultTTL, level, opt int,
	fakeSleep float64,
) error {
	if fakeSleep < 0.1 {
		fakeSleep = 0.1
	}
	toWrite := uint32(dataLen)

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
		return errors.New("TransmitFile call fialed")
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
	dataLen := len(fakeData)
	err = sendFakeData(
		sockHandle,
		fakeData,
		firstPacket[:dataLen],
		dataLen,
		fakeTTL,
		defaultTTL,
		level, opt,
		fakeSleep,
	)
	if err != nil {
		return fmt.Errorf("send first fake data: %v", err)
	}
	firstPacket = firstPacket[dataLen:]
	offset := sniLen/2 + sniPos - dataLen
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
	err = sendFakeData(
		sockHandle,
		fakeData,
		firstPacket[:dataLen],
		dataLen,
		fakeTTL,
		defaultTTL,
		level, opt,
		fakeSleep,
	)
	if err != nil {
		return fmt.Errorf("send second fake data: %v", err)
	}
	if _, err = conn.Write(firstPacket[dataLen:]); err != nil {
		return fmt.Errorf("send remaining data: %v", err)
	}

	return nil
}

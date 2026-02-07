//go:build linux

package main

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
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
	fd int,
	fakeData, realData []byte,
	fakeTTL, defaultTTL, level, opt int,
	fakeSleep time.Duration,
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

	err = unix.SetsockoptInt(int(fd), level, opt, fakeTTL)
	if err != nil {
		return fmt.Errorf("set fake ttl: %s", err)
	}
	iov := unix.Iovec{
		Base: &data[0],
		Len:  toUint(len(fakeData)),
	}
	if _, err := unix.Vmsplice(pipeW, []unix.Iovec{iov}, unix.SPLICE_F_GIFT); err != nil {
		return fmt.Errorf("vmsplice: %s", err)
	}
	if _, err := unix.Splice(pipeR, nil, fd, nil, len(fakeData), 0); err != nil {
		return fmt.Errorf("splice: %s", err)
	}
	time.Sleep(fakeSleep)

	copy(data, realData)

	err = unix.SetsockoptInt(int(fd), level, opt, defaultTTL)
	if err != nil {
		return fmt.Errorf("set default ttl: %s", err)
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
	var fd int
	err = rawConn.Control(func(fileDesc uintptr) {
		fd = int(fileDesc)
	})
	if err != nil {
		return fmt.Errorf("control: %w", err)
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
		return fmt.Errorf("get default ttl: %s", err)
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
		fd,
		fakeData,
		firstPacket[:cut],
		fakeTTL,
		defaultTTL,
		level, opt,
		fakeSleep,
	)
	if err != nil {
		return fmt.Errorf("first sending: %s", err)
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
		return fmt.Errorf("second sending: %s", err)
	}
	return nil
}

func sendOOB(conn net.Conn) error {
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
	if err = unix.Sendto(int(fd), []byte{'&'}, unix.MSG_OOB, nil); err != nil {
		return fmt.Errorf("unix.Sendto (MSG_OOB): %w", err)
	}
	return nil
}

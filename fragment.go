package main

import (
	"encoding/binary"
	"net"
	"strconv"
	"time"
)

func sendRecords(conn net.Conn, clientHello []byte,
	offset, length, records, segments int,
	oob, modMinorVer bool, interval time.Duration) error {
	if modMinorVer {
		clientHello[2] = 0x04
	}

	if records == 1 && segments > 1 {
		var leftSegments, rightSegments int
		if segments == 2 {
			leftSegments = 1
			rightSegments = 1
		} else {
			leftSegments = 2
			rightSegments = segments - leftSegments
		}
		packets := make([][]byte, 0, segments)
		cut, _ := findLastDot(clientHello, offset, length)
		splitAndAppend(clientHello[:cut], nil, leftSegments, &packets)
		splitAndAppend(clientHello[cut:], nil, rightSegments, &packets)
		for i, packet := range packets {
			if _, err := conn.Write(packet); err != nil {
				return wrap("write packet "+ strconv.Itoa(i+1), err)
			}
			if i == 0 && oob {
				if err := sendOOB(conn); err != nil {
					return wrap("oob", err)
				}
			}
			if interval > 0 {
				time.Sleep(interval)
			}
		}
		return nil
	}

	var leftChunks, rightChunks int
	if records == 2 {
		leftChunks = 1
		rightChunks = 1
	} else {
		leftChunks = 2
		rightChunks = records - leftChunks
	}
	chunks := make([][]byte, 0, records)
	cut, _ := findLastDot(clientHello, offset, length)
	header := clientHello[:3]
	splitAndAppend(clientHello[5:cut], header, leftChunks, &chunks)
	splitAndAppend(clientHello[cut:], header, rightChunks, &chunks)

	if segments == -1 {
		for i, chunk := range chunks {
			if _, err := conn.Write(chunk); err != nil {
				return wrap("write record "+ strconv.Itoa(i+1), err)
			}
			if i == 0 && oob {
				if err := sendOOB(conn); err != nil {
					return wrap("oob", err)
				}
			}
			if interval > 0 {
				time.Sleep(interval)
			}
		}
		return nil
	}

	merged := make([]byte, 0, records*3+len(clientHello))
	for _, c := range chunks {
		merged = append(merged, c...)
	}

	if segments == 1 || len(merged) <= segments {
		_, err := conn.Write(merged)
		return err
	}

	base := len(merged) / segments
	for i := range segments {
		start := i * base
		end := start + base
		if i == segments-1 {
			end = len(merged)
		}
		if _, err := conn.Write(merged[start:end]); err != nil {
			return wrap("write segment "+ strconv.Itoa(i+1), err)
		}
		if i == 0 && oob {
			if err := sendOOB(conn); err != nil {
				return wrap("oob", err)
			}
		}
		if interval > 0 {
			time.Sleep(interval)
		}
	}
	return nil
}

func splitAndAppend(data, header []byte, n int, result *[][]byte) {
	if n <= 0 {
		return
	}
	addHeader := header != nil
	if n == 1 || len(data) < n {
		if addHeader {
			*result = append(*result, makeRecord(header, data))
		} else {
			*result = append(*result, data)
		}
		return
	}
	base := len(data) / n
	for i := range n {
		var part []byte
		if i == n-1 {
			part = data[i*base:]
		} else {
			part = data[i*base : (i+1)*base]
		}
		if addHeader {
			*result = append(*result, makeRecord(header, part))
		} else {
			*result = append(*result, part)
		}
	}
}

func makeRecord(header, payload []byte) []byte {
	rec := make([]byte, 5+len(payload))
	copy(rec[:3], header)
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(payload)))
	copy(rec[5:], payload)
	return rec
}

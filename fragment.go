package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

func sendRecords(conn net.Conn, data []byte,
	offset, length, numRcd, numSeg int,
	oob, modMinorVer bool, interval time.Duration) error {
	if len(data) < 5 {
		return errors.New("data too short")
	}
	if numRcd <= 0 {
		return errors.New("invalid numRcd")
	}
	if numSeg != 1 && numSeg != -1 && numSeg <= 0 {
		return errors.New("invalid numSeg")
	}
	if length < 4 {
		return errors.New("invalid length")
	}

	header := data[:3]
	if modMinorVer {
		header[2] = 0x04
	}
	offset -= 5
	cut := offset + 1 + 2

	rightChunks := numRcd / 2
	leftChunks := numRcd - rightChunks

	chunks := make([][]byte, 0, numRcd)
	splitAndAppend(data[5:cut], header, leftChunks, &chunks)
	splitAndAppend(data[cut:], header, rightChunks, &chunks)

	if numSeg == -1 {
		for i, chunk := range chunks {
			if _, err := conn.Write(chunk); err != nil {
				return fmt.Errorf("write record %d: %s", i+1, err)
			}
			if i == 0 && oob {
				if err := sendOOB(conn); err != nil {
					return fmt.Errorf("oob: %s", err)
				}
			}
			if interval > 0 {
				time.Sleep(interval)
			}
		}
		return nil
	}

	total := 0
	for _, c := range chunks {
		total += len(c)
	}
	merged := make([]byte, 0, total)
	for _, c := range chunks {
		merged = append(merged, c...)
	}

	if numSeg == 1 || len(merged) <= numSeg {
		_, err := conn.Write(merged)
		return err
	}

	base := len(merged) / numSeg
	for i := range numSeg {
		start := i * base
		end := start + base
		if i == numSeg-1 {
			end = len(merged)
		}
		if _, err := conn.Write(merged[start:end]); err != nil {
			return fmt.Errorf("write segment %d: %s", i+1, err)
		}
		if i == 0 && oob {
			if err := sendOOB(conn); err != nil {
				return fmt.Errorf("oob: %s", err)
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
	if n == 1 || len(data) < n {
		*result = append(*result, makeRecord(header, data))
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
		*result = append(*result, makeRecord(header, part))
	}
}

func makeRecord(header, payload []byte) []byte {
	rec := make([]byte, 5+len(payload))
	copy(rec[:3], header)
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(payload)))
	copy(rec[5:], payload)
	return rec
}

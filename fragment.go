package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"time"
)

func sendRecords(conn net.Conn, data []byte, offset, length, numRcd, numSeg int, interval *float64) error {
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

	header := make([]byte, 3)
	copy(header, data[:3])
	payload := data[5:]
	offset -= 5

	if offset < -1 {
		return errors.New("adjusted offset < -1")
	}
	if offset+length > len(payload) {
		return errors.New("slice out of payload bounds")
	}

	cut := offset + 1 + rand.Intn(length-1)

	rightChunks := numRcd / 2
	leftChunks := numRcd - rightChunks

	chunks := make([][]byte, 0, numRcd)
	splitAndAppend(payload[:cut], header, leftChunks, &chunks)
	splitAndAppend(payload[cut:], header, rightChunks, &chunks)

	if numSeg == -1 {
		for _, chunk := range chunks {
			_, err := conn.Write(chunk)
			if err != nil {
				return err
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
	itv := interval != nil && *interval > 0
	for i := range numSeg {
		start := i * base
		end := start + base
		if i == numSeg-1 {
			end = len(merged)
		}
		if _, err := conn.Write(merged[start:end]); err != nil {
			return fmt.Errorf("segment %d write error: %w", i, err)
		}
		if itv {
			time.Sleep(time.Duration(*interval * float64(time.Second)))
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
	h := make([]byte, len(header))
	copy(h, header)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(payload)))
	rec := append(h, l[:]...)
	rec = append(rec, payload...)
	return rec
}

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"sync"

	log "github.com/moi-si/mylog"
)

const (
	socks5RepSuccess          byte = 0x00
	socks5RepServerFailure    byte = 0x01
	socks5RepConnNotAllowed   byte = 0x02
	socks5RepCmdNotSupported  byte = 0x07
	socks5RepAtypNotSupported byte = 0x08
)

func socks5Accept(addr *string, serverAddr string, done chan struct{}) {
	defer func() { done <- struct{}{} }()
	var listenAddr string
	if *addr == "" {
		listenAddr = serverAddr
	} else {
		listenAddr = *addr
	}
	if listenAddr == "" {
		fmt.Println("SOCKS5 bind address not specified")
		return
	}
	if listenAddr == "none" {
		return
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Println("SOCKS5 Listen error:", err)
		return
	}
	if listenAddr[0] == ':' {
		listenAddr = "0.0.0.0" + listenAddr
	}
	logger := log.New(os.Stdout, "[S00000]", log.LstdFlags, logLevel)
	logger.Info("Listening on", "socks5://"+listenAddr)

	var connID uint32
	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.Error("Accept:", err)
		} else {
			connID += 1
			if connID > 0xFFFFF {
				connID = 0
			}
			go handleSOCKS5(conn, connID)
		}
	}
}

func readN(conn net.Conn, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(conn, buf)
	return buf, err
}

func sendReply(logger *log.Logger, conn net.Conn, rep byte) {
	resp := []byte{0x05, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(resp); err != nil {
		logger.Debug("Send SOCKS5 reply:", err)
	}
}

func handleSOCKS5(cliConn net.Conn, id uint32) {
	logger := log.New(os.Stdout, fmt.Sprintf("[S%05x]", id), log.LstdFlags, logLevel)
	logger.Info("Connection from", cliConn.RemoteAddr().String())

	var (
		once    sync.Once
		dstConn net.Conn
	)
	closeBoth := func() {
		once.Do(func() {
			if err := cliConn.Close(); err != nil {
				logger.Debug("Close client conn:", err)
			}
			if dstConn != nil {
				if err := dstConn.Close(); err != nil {
					logger.Debug("Close dest conn:", err)
				}
			}
			logger.Debug("Connection closed")
		})
	}
	defer closeBoth()

	header, err := readN(cliConn, 2)
	if err != nil {
		logger.Error("Read method selection:", err)
		return
	}
	if header[0] != 0x05 {
		logger.Error("Not SOCKS5:", header[0])
		return
	}
	nMethods := int(header[1])
	methods, err := readN(cliConn, nMethods)
	if err != nil {
		logger.Error("Read methods:", err)
		return
	}
	var authMethod byte = 0xFF
	if slices.Contains(methods, 0x00) {
		authMethod = 0x00
	}
	if _, err = cliConn.Write([]byte{0x05, authMethod}); err != nil {
		logger.Error("Method write:", err)
		return
	}
	if authMethod == 0xFF {
		logger.Error("No `no auth` method")
		return
	}

	header, err = readN(cliConn, 4)
	if err != nil {
		logger.Error("Read req header:", err)
		return
	}
	if header[0] != 0x05 {
		logger.Error("Invalid version:", header[0])
		return
	}
	if header[1] != 0x01 {
		logger.Error("Not CONNECT:", header[1])
		sendReply(logger, cliConn, socks5RepCmdNotSupported)
		return
	}

	var (
		originHost, dstHost string
		policy              Policy
	)
	switch header[3] {
	case 0x01: // IPv4 address
		ipBytes, err := readN(cliConn, 4)
		if err != nil {
			logger.Error("Read IPv4:", err)
			return
		}
		originHost = net.IP(ipBytes).String()
		var ipPolicy *Policy
		dstHost, ipPolicy, err = ipRedirect(logger, originHost)
		if err != nil {
			logger.Error("IP redirect:", err)
			sendReply(logger, cliConn, socks5RepServerFailure)
			return
		}
		if ipPolicy == nil {
			policy = defaultPolicy
		} else {
			policy = mergePolicies(ipPolicy, &defaultPolicy)
		}
	case 0x04: // IPv6 address
		ipBytes, err := readN(cliConn, 16)
		if err != nil {
			logger.Error("Read IPv6:", err)
			return
		}
		originHost = net.IP(ipBytes).String()
		var ipPolicy *Policy
		dstHost, ipPolicy, err = ipRedirect(logger, originHost)
		if err != nil {
			logger.Error("IP redirect:", err)
			sendReply(logger, cliConn, socks5RepServerFailure)
			return
		}
		if ipPolicy == nil {
			policy = defaultPolicy
		} else {
			policy = mergePolicies(ipPolicy, &defaultPolicy)
		}
	case 0x03: // Domain name
		lenByte, err := readN(cliConn, 1)
		if err != nil {
			logger.Error("Read domain length:", err)
			return
		}
		domainBytes, err := readN(cliConn, int(lenByte[0]))
		if err != nil {
			logger.Error("Read domain:", err)
		}
		originHost = string(domainBytes)
		var fail, block bool
		dstHost, policy, fail, block = genPolicy(logger, originHost)
		if fail {
			sendReply(logger, cliConn, 0x01)
			return
		}
		if block {
			logger.Error("Blocked connection to", originHost)
			if policy.ReplyFirst == BoolTrue {
				sendReply(logger, cliConn, socks5RepSuccess)
			} else {
				sendReply(logger, cliConn, socks5RepConnNotAllowed)
			}
			return
		}
	default:
		logger.Error("Invalid address type:", header[3])
		sendReply(logger, cliConn, socks5RepAtypNotSupported)
		return
	}
	portBytes, err := readN(cliConn, 2)
	if err != nil {
		logger.Error("Read port:", err)
		return
	}
	dstPort := binary.BigEndian.Uint16(portBytes)
	oldTarget := net.JoinHostPort(originHost, fmt.Sprintf("%d", dstPort))
	logger.Info("CONNECT", oldTarget)
	logger.Info("Policy:", policy)
	if policy.Mode == ModeBlock {
		sendReply(logger, cliConn, socks5RepConnNotAllowed)
		return
	}
	if policy.Port != 0 && policy.Port != -1 {
		dstPort = uint16(policy.Port)
	}
	target := net.JoinHostPort(dstHost, strconv.FormatUint(uint64(dstPort), 10))

	replyFirst := policy.ReplyFirst == BoolTrue
	if !replyFirst {
		dstConn, err = net.DialTimeout("tcp", target, policy.ConnectTimeout)
		if err != nil {
			logger.Error("Connection failed:", err)
			sendReply(logger, cliConn, socks5RepServerFailure)
			return
		}
	}
	sendReply(logger, cliConn, socks5RepSuccess)

	handleTunnel(policy, replyFirst, dstConn, cliConn,
		logger, target, originHost, closeBoth)
}

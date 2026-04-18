package lumine

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"slices"

	log "github.com/moi-si/mylog"
)

var (
	noAuthReply                 = [2]byte{0x5, 0x0}
	socks5ReplySuccess          = [10]byte{0x5, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
	socks5ReplyServerFailure    = [10]byte{0x5, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
	socks5ReplyConnNotAllowed   = [10]byte{0x5, 0x2, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
	socks5ReplyCmdNotSupported  = [10]byte{0x5, 0x7, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
	socks5ReplyAtypNotSupported = [10]byte{0x5, 0x8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
)

func SOCKS5Accept(addr *string, serverAddr string, done chan struct{}) {
	defer func() { done <- struct{}{} }()
	var listenAddr string
	if *addr == "" {
		listenAddr = serverAddr
	} else {
		listenAddr = *addr
	}
	if listenAddr == "" {
		fmt.Println("SOCKS5 bind address is not specified")
		return
	}
	if listenAddr == "none" {
		return
	}

	logger := log.New(os.Stdout, "[S00000]", log.LstdFlags, logLevel)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		logger.Error("Failed to start SOCKS5 server:", err)
		return
	}
	logger.Info("SOCKS5 proxy server started at", ln.Addr())

	var connID uint32
	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.Error("Accept:", err)
		} else {
			connID += 1
			if connID > 0xFFFFF {
				connID = 1
			}
			go socks5Handler(conn, connID)
		}
	}
}

func readN(conn net.Conn, buf []byte) ([]byte, error) {
	_, err := io.ReadFull(conn, buf)
	return buf, err
}

func sendReply(logger *log.Logger, conn net.Conn, reply [10]byte) bool {
	if _, err := conn.Write(reply[:]); err != nil {
		logger.Error("Send SOCKS5 reply:", err)
		return false
	}
	return true
}

func socks5Handler(cliConn net.Conn, id uint32) {
	logger := log.New(os.Stdout, fmt.Sprintf("[S%05x]", id), log.LstdFlags, logLevel)
	logger.Info("Connection from", cliConn.RemoteAddr())

	var (
		closeHere = true
		dstConn   net.Conn
	)
	defer func() {
		if closeHere {
			if err := cliConn.Close(); err == nil {
				logger.Debug("Closed client conn")
			} else {
				logger.Debug("Close client conn:", err)
			}
		}
	}()

	var headerBuf [2]byte
	header, err := readN(cliConn, headerBuf[:])
	if err != nil {
		logger.Error("Read method selection:", err)
		return
	}
	if header[0] != 0x5 {
		logger.Error("Expected socks version 5, but got", byteToString(header[0]))
		return
	}

	var buf [256]byte
	methods, err := readN(cliConn, buf[:header[1]])
	if err != nil {
		logger.Error("Read methods:", err)
		return
	}

	if !slices.Contains(methods, 0x0) {
		logger.Error("`no auth` method not found")
		return
	}
	if _, err = cliConn.Write(noAuthReply[:]); err != nil {
		logger.Error("Send auth method:", err)
		return
	}

	header, err = readN(cliConn, buf[:4])
	if err != nil {
		logger.Error("Read request header:", err)
		return
	}
	if header[0] != 0x5 {
		logger.Error("Expected socks version 5, but got", byteToString(header[0]))
		return
	}
	if header[1] != 0x1 {
		logger.Error("Expected cmd CONNECT, but got", byteToString(header[1]))
		sendReply(logger, cliConn, socks5ReplyCmdNotSupported)
		return
	}

	var (
		originHost, dstHost string
		policy              *Policy
		isIP                bool
	)
	switch header[3] {
	case 0x1: // IPv4 address
		ipBytes, err := readN(cliConn, buf[:4])
		if err != nil {
			logger.Error("Read IPv4 address:", err)
			return
		}
		originHost = net.IP(ipBytes).String()
		isIP = true
	case 0x4: // IPv6 address
		ipBytes, err := readN(cliConn, buf[:16])
		if err != nil {
			logger.Error("Read IPv6 address:", err)
			return
		}
		originHost = net.IP(ipBytes).String()
		isIP = true
	case 0x3: // Domain name
		lenByte, err := readN(cliConn, buf[:1])
		if err != nil {
			logger.Error("Read domain length:", err)
			return
		}
		if lenByte[0] > 253 {
			logger.Error("Domain length too long:", lenByte[0])
			return
		}
		domainBytes, err := readN(cliConn, buf[:lenByte[0]])
		if err != nil {
			logger.Error("Read domain address:", err)
		}
		originHost = string(domainBytes)
	default:
		logger.Error("Invalid atyp:", byteToString(header[3]))
		sendReply(logger, cliConn, socks5ReplyAtypNotSupported)
		return
	}

	dstHost, policy, failed, blocked, _ := genPolicy(logger, originHost, isIP, false)
	if failed {
		sendReply(logger, cliConn, socks5ReplyServerFailure)
		return
	}
	if blocked {
		logger.Info("Connection blocked:", originHost)
		sendReply(logger, cliConn, socks5ReplyConnNotAllowed)
		return
	}

	portBytes, err := readN(cliConn, buf[:2])
	if err != nil {
		logger.Error("Read port:", err)
		return
	}
	dstPort := binary.BigEndian.Uint16(portBytes)
	originPort := formatUint(dstPort)
	oldTarget := net.JoinHostPort(originHost, originPort)

	logger.Info("CONNECT", oldTarget)
	logger.Info("Policy:", policy)
	if policy.Port != 0 && policy.Port != unsetInt {
		dstPort = uint16(policy.Port)
	}
	target := net.JoinHostPort(dstHost, formatUint(dstPort))

	if policy.ReplyFirst != BoolTrue {
		dstConn, err = dialTCPTimeout(target, policy.ConnectTimeout)
		if err != nil {
			logger.Error("Connection to", oldTarget, "failed:", err)
			sendReply(logger, cliConn, socks5ReplyServerFailure)
			return
		}
	}
	if !sendReply(logger, cliConn, socks5ReplySuccess) {
		return
	}

	closeHere = false
	handleTunnel(policy, dstConn, cliConn, logger, oldTarget, target, originHost, originPort)
}

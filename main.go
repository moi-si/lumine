package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"
	"sync"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "moi-si/lumine v0.3.0")
		fmt.Fprintln(os.Stderr)
		flag.PrintDefaults()
	}
	configPath := flag.String("c", "config.json", "Config file path")
	addr := flag.String("b", "", "SOCKS5 bind address (default: address from config file)")
	hAddr := flag.String("hb", "", "HTTP bind address (default: address from config file)")

	flag.Parse()

	socks5Addr, httpAddr, err := loadConfig(*configPath)
	if err != nil {
		fmt.Println("Failed to load config:", err)
		return
	}

	done := make(chan struct{})
	go socks5Accept(addr, socks5Addr, done)
	go httpAccept(hAddr, httpAddr, done)
	<-done
	<-done
}

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
	fmt.Println("Listening on", "socks5://"+listenAddr)

	var connID uint32
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("SOCKS5 accept error: %s", err)
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
		logger.Println("Send SOCKS5 reply fail:", err)
	}
}

func handleSOCKS5(clientConn net.Conn, id uint32) {
	var (
		once    sync.Once
		dstConn net.Conn
	)
	closeBoth := func() {
		once.Do(func() {
			clientConn.Close()
			if dstConn != nil {
				dstConn.Close()
			}
		})
	}
	defer closeBoth()

	logger := log.New(os.Stdout, fmt.Sprintf("[S%05x] ", id), log.LstdFlags)
	logger.Println("Connection from", clientConn.RemoteAddr().String())

	header, err := readN(clientConn, 2)
	if err != nil {
		logger.Println("Read method selection fail:", err)
		return
	}
	if header[0] != 0x05 {
		logger.Println("Not SOCKS5:", header[0])
		return
	}
	nMethods := int(header[1])
	methods, err := readN(clientConn, nMethods)
	if err != nil {
		logger.Println("Read methods fail:", err)
		return
	}
	var authMethod byte = 0xFF
	if slices.Contains(methods, 0x00) {
		authMethod = 0x00
	}
	if _, err = clientConn.Write([]byte{0x05, authMethod}); err != nil {
		logger.Println("Method write fail:", err)
		return
	}
	if authMethod == 0xFF {
		logger.Println("No `no auth` method")
		return
	}

	header, err = readN(clientConn, 4)
	if err != nil {
		logger.Println("Read req header fail:", err)
		return
	}
	if header[0] != 0x05 {
		logger.Println("Ver err:", header[0])
		return
	}
	if header[1] != 0x01 {
		logger.Println("Not CONNECT:", header[1])
		sendReply(logger, clientConn, 0x07)
		return
	}

	var (
		originHost, dstHost string
		policy              *Policy
	)
	switch header[3] {
	case 0x01: // IPv4 address
		ipBytes, err := readN(clientConn, 4)
		if err != nil {
			logger.Println("Read IPv4 fail:", err)
			return
		}
		originHost = net.IP(ipBytes).String()
		var ipPolicy *Policy
		dstHost, ipPolicy, err = ipRedirect(logger, originHost)
		if err != nil {
			logger.Println("IP redirect error:", err)
			sendReply(logger, clientConn, 0x01)
			return
		}
		if ipPolicy == nil {
			policy = &defaultPolicy
		} else {
			policy = mergePolicies(*ipPolicy, defaultPolicy)
		}
	case 0x04: // IPv6 address
		ipBytes, err := readN(clientConn, 16)
		if err != nil {
			logger.Println("Read IPv6 fail", err)
			return
		}
		originHost = net.IP(ipBytes).String()
		var ipPolicy *Policy
		dstHost, ipPolicy, err = ipRedirect(logger, originHost)
		if err != nil {
			logger.Println("IP redirect error:", err)
			sendReply(logger, clientConn, 0x01)
			return
		}
		if ipPolicy == nil {
			policy = &defaultPolicy
		} else {
			policy = mergePolicies(*ipPolicy, defaultPolicy)
		}
	case 0x03: // Domain name
		lenByte, err := readN(clientConn, 1)
		if err != nil {
			logger.Println("Read domain len fail:", err)
			return
		}
		domainBytes, err := readN(clientConn, int(lenByte[0]))
		if err != nil {
			logger.Println("Read domain fail:", err)
		}
		originHost = string(domainBytes)
		var fail, block bool
		dstHost, policy, fail, block = genPolicy(logger, originHost)
		if fail {
			sendReply(logger, clientConn, 0x01)
			return
		}
		if block {
			logger.Printf("Blocked connection to %s", originHost)
			sendReply(logger, clientConn, 0x02)
			return
		}
	default:
		logger.Println("Invalid address type:", header[3])
		sendReply(logger, clientConn, 0x08)
		return
	}
	portBytes, err := readN(clientConn, 2)
	if err != nil {
		logger.Println("Read port fail:", err)
		return
	}
	dstPort := binary.BigEndian.Uint16(portBytes)
	oldTarget := net.JoinHostPort(originHost, fmt.Sprintf("%d", dstPort))
	logger.Println("CONNECT", oldTarget)
	logger.Println("Policy:", policy)
	if policy.Mode == ModeBlock {
		sendReply(logger, clientConn, 0x02)
		return
	}
	if policy.Port != 0 && policy.Port != -1 {
		dstPort = uint16(policy.Port)
	}
	target := net.JoinHostPort(dstHost, fmt.Sprintf("%d", dstPort))

	replyFirst := policy.ReplyFirst == BoolTrue
	if !replyFirst {
		dstConn, err = net.DialTimeout("tcp", target, policy.ConnectTimeout)
		if err != nil {
			logger.Println("Connection failed:", err)
			sendReply(logger, clientConn, 0x01)
			return
		}
	}
	sendReply(logger, clientConn, 0x00)

	handleTunnel(policy, replyFirst, dstConn, clientConn,
		logger, target, originHost, closeBoth)
}

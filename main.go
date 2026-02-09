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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
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
	var closeHere = true
	defer func() {
		if closeHere {
			clientConn.Close()
		}
	}()

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

	switch header[1] {
	case 0x01:
		closeHere = false
		handleSocksConnect(logger, header[3], clientConn)
	case 0x03:
		closeHere = false
		handleSocksUDP(logger, header[3], clientConn)
	default:
		logger.Printf("Unsupported CMD: %#x", header[1])
		sendReply(logger, clientConn, 0x07)
	}
}

func handleSocksConnect(logger *log.Logger, atyp byte, clientConn net.Conn) {
	var (
		originHost, dstHost string
		policy              *Policy
		dstConn             net.Conn
		once                sync.Once
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

	switch atyp {
	case 0x01: // IPv4 address
		ipBytes, err := readN(clientConn, 4)
		if err != nil {
			logger.Println("CONNECT: read IPv4 fail:", err)
			return
		}
		originHost = net.IP(ipBytes).String()
		var ipPolicy *Policy
		dstHost, ipPolicy, err = ipRedirect(logger, originHost)
		if err != nil {
			logger.Println("CONNECT: IP redirect error:", err)
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
			logger.Println("CONNECT: read IPv6 fail", err)
			return
		}
		originHost = net.IP(ipBytes).String()
		var ipPolicy *Policy
		dstHost, ipPolicy, err = ipRedirect(logger, originHost)
		if err != nil {
			logger.Println("CONNECT: IP redirect error:", err)
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
			logger.Println("CONNECT: read domain len fail:", err)
			return
		}
		domainBytes, err := readN(clientConn, int(lenByte[0]))
		if err != nil {
			logger.Println("CONNECT: read domain fail:", err)
		}
		originHost = string(domainBytes)
		var fail, block bool
		dstHost, policy, fail, block = genPolicy(logger, originHost)
		if fail {
			sendReply(logger, clientConn, 0x01)
			return
		}
		if block {
			logger.Printf("CONNECT: blocked connection to %s", originHost)
			sendReply(logger, clientConn, 0x02)
			return
		}
	default:
		logger.Printf("CONNECT: invalid address type: %#x", atyp)
		sendReply(logger, clientConn, 0x08)
		return
	}
	portBytes, err := readN(clientConn, 2)
	if err != nil {
		logger.Println("CONNECT: read port fail:", err)
		return
	}
	dstPort := binary.BigEndian.Uint16(portBytes)
	oldTarget := net.JoinHostPort(originHost, strconv.Itoa(int(dstPort)))
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

func handleSocksUDP(logger *log.Logger, atyp byte, clientConn net.Conn) {
	defer clientConn.Close()

	var dstAddr string
	switch atyp {
	case 0x01:
		ipBytes, err := readN(clientConn, 4)
		if err != nil {
			logger.Println("UDP ASSOCIATE: read IPv4 fail:", err)
			return
		}
		dstAddr = net.IP(ipBytes).String()
	case 0x04:
		ipBytes, err := readN(clientConn, 16)
		if err != nil {
			logger.Println("UDP ASSOCIATE: read IPv6 fail", err)
			return
		}
		dstAddr = net.IP(ipBytes).String()
	default:
		logger.Printf("UDP ASSOCIATE: invalid address type: %#x", atyp)
		sendReply(logger, clientConn, 0x08)
		return
	}
	portBytes, err := readN(clientConn, 2)
	if err != nil {
		logger.Println("UDP ASSOCIATE: read port fail:", err)
		return
	}
	dstPort := binary.BigEndian.Uint16(portBytes)
	oldTarget := net.JoinHostPort(dstAddr, strconv.Itoa(int(dstPort)))
	if oldTarget != "0.0.0.0:0" && oldTarget != "[::]:0" {
		logger.Println("UDP ASSOCIATE: bad target:", oldTarget)
		return
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   clientConn.LocalAddr().(*net.TCPAddr).IP,
		Port: 0,
	})
	if err != nil {
		logger.Println("UDP ASSOCIATE: listen error:", err)
		return
	}
	defer conn.Close()
	addr := conn.LocalAddr().(*net.UDPAddr)
	bndHost := addr.IP
	bndPort := addr.Port
	logger.Println("UDP listening on", net.JoinHostPort(bndHost.String(), strconv.Itoa(bndPort)))

	var reply []byte
	if bndHost.To4() != nil {
		reply = make([]byte, 10)
		copy(reply[:4], []byte{0x05, 0x00, 0x00, 0x01})
		copy(reply[4:8], bndHost)
		binary.BigEndian.PutUint16(reply[8:10], uint16(bndPort))
	} else {
		reply = make([]byte, 22)
		copy(reply[:4], []byte{0x05, 0x00, 0x00, 0x04})
		copy(reply[4:20], bndHost)
		binary.BigEndian.PutUint16(reply[20:22], uint16(bndPort))
	}
	if _, err := clientConn.Write(reply); err != nil {
		logger.Println("Send reply fail:", err)
		return
	}

	clientHost := clientConn.RemoteAddr().(*net.TCPAddr).IP

	quit := make(chan struct{}, 1)

	go func() {
		defer close(quit)
		buf := make([]byte, 1)
		for {
			if err := clientConn.SetDeadline(time.Now().Add(time.Second)); err != nil {
				break
			}
			n, err := clientConn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				break
			}
			if n == 0 {
				break
			}
		}
		conn.Close()
	}()

	buf := make([]byte, 1500)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-quit:
				logger.Println("TCP control connection closed")
				return
			default:
				if !strings.Contains(err.Error(), "closed") {
					logger.Println("UDP read error:", err)
				}
				return
			}
		}
		if !clientAddr.IP.Equal(clientHost) {
			logger.Println("Dropped datagram from", clientAddr)
			continue
		}
		logger.Println("Received datagram from", clientAddr)
		if n <= 10 {
			logger.Println("Datagram from", clientAddr, "is too short")
			continue
		}
		msg := buf[:n]
		if msg[0] != 0x00 && msg[1] != 0x00 {
			logger.Printf("Invalid RSV: 0x%02x 0x%02x", msg[0], msg[1])
			continue
		}
		if msg[2] != 0x00 {
			logger.Printf("Invalid FRAG: 0x%02x", msg[2])
			continue
		}

		var dstHost string
		offset := 4
		switch msg[3] {
		case 0x01:
			if offset+4 >= n {
				logger.Println("Datagram from", clientAddr, "is too short")
				continue
			}
			dstHost = net.IP(msg[offset : offset+4]).String()
			if ipPolicy := getIPPolicy(dstHost); ipPolicy != nil {
				if ipPolicy.Mode == ModeBlock {
					logger.Println("Dropped datagram to", dstHost)
					continue
				}
			} else if defaultPolicy.Mode == ModeBlock {
				logger.Println("Dropped datagram to", dstHost)
				continue
			}
			offset += 4
		case 0x04:
			if offset+16 >= n {
				logger.Println("Datagram from", clientAddr, "is too short")
				continue
			}
			dstHost = net.IP(msg[offset : offset+16]).String()
			if ipPolicy := getIPPolicy(dstHost); ipPolicy != nil {
				if ipPolicy.Mode == ModeBlock {
					logger.Println("Dropped datagram to", dstHost)
					continue
				}
			} else if defaultPolicy.Mode == ModeBlock {
				logger.Println("Dropped datagram to", dstHost)
				continue
			}
			offset += 16
		case 0x03:
			length := int(msg[4])
			offset++
			domain := string(msg[offset : offset+length])
			if offset+length >= n {
				logger.Println("Datagram from", clientAddr, "is too short")
				continue
			}
			offset += length
			var policy *Policy
			if domainPolicy := domainMatcher.Find(domain); domainPolicy != nil {
				policy = mergePolicies(*domainPolicy, defaultPolicy)
			} else {
				policy = &defaultPolicy
			}
			if policy.Mode == ModeBlock {
				logger.Println("Dropped datagram to", domain)
				continue
			}

			var cached bool
			if policy.DNSRetry == BoolTrue {
				var first, second uint16
				var err1, err2 error
				if policy.IPv6First == BoolTrue {
					first = dns.TypeAAAA
					second = dns.TypeA
				} else {
					first = dns.TypeA
					second = dns.TypeAAAA
				}
				dstHost, cached, err1, err2 = doubleQuery(domain, first, second)
				if err2 != nil {
					logger.Printf("Resolve %s fail: (%s, %s)", domain, err1, err2)
					continue
				}
			} else {
				dstHost, cached, err = dnsQuery(domain, dns.TypeA)
				if err != nil {
					logger.Println("Resolve", domain, "fail:", err)
					continue
				}
			}
			if cached {
				logger.Println("DNS(cache):", domain, "->", dstHost)
			} else {
				logger.Println("DNS:", domain, "->", dstHost)
			}
		default:
			logger.Printf("Invalid atyp: 0x%02x", msg[3])
			continue
		}

		if offset+2 >= n {
			logger.Println("Datagram from", clientAddr, "is too short")
			continue
		}
		dstPort := binary.BigEndian.Uint16(msg[offset : offset+2])
		offset += 2
		dstAddr := net.JoinHostPort(dstHost, strconv.FormatUint(uint64(dstPort), 10))
		logger.Println("UDP to", dstAddr)

		if len(msg[offset:]) > 20 && msg[offset] == 0x00 && msg[offset+1] == 0x01 {
			logger.Println("Blocked STUN binding request to", dstAddr)
			return
		}

		dstConn, err := net.DialUDP("udp", nil, &net.UDPAddr{
			IP:   net.ParseIP(dstHost),
			Port: int(dstPort),
		})
		if err != nil {
			logger.Println("Dial", oldTarget, "fail:", err)
			continue
		}

		go func() {
			defer dstConn.Close()
			if _, err := dstConn.Write(msg[offset:]); err != nil {
				logger.Println("Send to", dstAddr, "fail:", err)
				return
			}
			buf := make([]byte, 1500)
			dstConn.SetDeadline(time.Now().Add(10 * time.Second))
			n, err := dstConn.Read(buf)
			if err != nil {
				logger.Println("Read from", dstAddr, "fail:", err)
				return
			}

			resp := make([]byte, offset+n)
			copy(resp[:offset], msg[:offset])
			copy(resp[offset:offset+n], buf[:n])
			if _, err := conn.WriteToUDP(resp, clientAddr); err != nil {
				logger.Println("Send back to", clientAddr, "fail:", err)
			} else {
				logger.Println("Successfully sent response to", clientAddr)
			}
		}()
	}
}

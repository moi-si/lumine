package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
)

var connID uint32

func makeLogger() *log.Logger {
	id := atomic.AddUint32(&connID, 1)
	if id > 0xFFFF {
		atomic.StoreUint32(&connID, 0)
		id = 0
	}
	return log.New(os.Stdout, fmt.Sprintf("[%05x] ", id), log.LstdFlags)
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

func ipRedirect(logger *log.Logger, ip string) (string, *Policy, error) {
	for range maxJump {
		policy := matchIP(ip)
		if policy == nil {
			return ip, nil, nil
		}
		if policy.MapTo == nil || *policy.MapTo == "" {
			return ip, policy, nil
		}

		mapTo := *policy.MapTo
		var chain bool
		if mapTo[0] == '^' {
			mapTo = mapTo[1:]
		} else {
			chain = true
		}
		if strings.Contains(mapTo, "/") {
			var err error
			mapTo, err = transformIP(ip, mapTo)
			if err != nil {
				return "", nil, err
			}
		}
		if ip == mapTo {
			return ip, policy, nil
		}
		logger.Printf("Redirect %s to %s", ip, mapTo)

		if chain {
			ip = mapTo
			continue
		}
		return mapTo, matchIP(mapTo), nil
	}
	return "", nil, errors.New("too many redirects")
}

func handleClient(clientConn net.Conn) {
	defer clientConn.Close()
	logger := makeLogger()
	logger.Println("Conn from", clientConn.RemoteAddr().String())

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

	var dstAddr, dstHost string
	var policy *Policy
	switch header[3] {
	case 0x01: // IPv4 address
		ipBytes, err := readN(clientConn, 4)
		if err != nil {
			logger.Println("Read IPv4 fail:", err)
			return
		}
		dstAddr = net.IP(ipBytes).String()
		var ipPolicy *Policy
		dstHost, ipPolicy, err = ipRedirect(logger, dstAddr)
		if err != nil {
			logger.Println("IP redirect error:", err)
			return
		}
		if ipPolicy == nil {
			policy = &defaultPolicy
		} else {
			policy = mergePolicies(defaultPolicy, *ipPolicy)
		}
	case 0x04: // IPv6 address
		ipBytes, err := readN(clientConn, 16)
		if err != nil {
			logger.Println("Read IPv6 fail", err)
			return
		}
		dstAddr = net.IP(ipBytes).String()
		var ipPolicy *Policy
		dstHost, ipPolicy, err = ipRedirect(logger, dstAddr)
		if err != nil {
			logger.Println("IP redirect error:", err)
			return
		}
		if ipPolicy == nil {
			policy = &defaultPolicy
		} else {
			policy = mergePolicies(defaultPolicy, *ipPolicy)
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
			return
		}
		dstAddr = string(domainBytes)
		// For Firefox
		if net.ParseIP(dstAddr) != nil {
			var ipPolicy *Policy
			dstHost, ipPolicy, err = ipRedirect(logger, dstAddr)
			if err != nil {
				logger.Println("IP redirect error:", err)
				return
			}
			if ipPolicy == nil {
				policy = &defaultPolicy
			} else {
				policy = mergePolicies(defaultPolicy, *ipPolicy)
			}
		} else {
			domainPolicy := domainMatcher.Find(dstAddr)
			found := domainPolicy != nil
			if found {
				policy = mergePolicies(defaultPolicy, *domainPolicy)
			} else {
				policy = &defaultPolicy
			}
			var disableRedirect bool
			if policy.Host == nil || *policy.Host == "" {
				var first uint16
				if policy.IPv6First != nil && *policy.IPv6First {
					first = dns.TypeAAAA
				} else {
					first = dns.TypeA
				}
				if policy.DNSRetry != nil && *policy.DNSRetry {
					var second uint16
					if first == dns.TypeA {
						second = dns.TypeAAAA
					} else {
						second = dns.TypeA
					}
					var err1, err2 error
					dstHost, err1, err2 = doubleQuery(dstAddr, first, second)
					if err2 != nil {
						logger.Printf("DNS %s fail: %s, %s", dstAddr, err1, err2)
						sendReply(logger, clientConn, 0x01)
						return
					}
				} else {
					var err error
					dstHost, err = dnsQuery(dstAddr, first)
					if err != nil {
						logger.Printf("DNS %s fail: %s", dstAddr, err)
						sendReply(logger, clientConn, 0x01)
						return
					}
					logger.Printf("DNS %s -> %s", dstAddr, dstHost)
				}
			} else {
				disableRedirect = (*policy.Host)[0] == '^'
				if disableRedirect {
					dstHost = (*policy.Host)[1:]
				} else {
					dstHost = *policy.Host
				}
			}
			var ipPolicy *Policy
			if !disableRedirect {
				dstHost, ipPolicy, err = ipRedirect(logger, dstHost)
				if err != nil {
					logger.Println("IP redirect error:", err)
					return
				}
				if ipPolicy != nil {
					if found {
						policy = mergePolicies(defaultPolicy, *ipPolicy, *domainPolicy)
					} else {
						policy = mergePolicies(defaultPolicy, *ipPolicy)
					}
				}
			}
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
	oldTarget := net.JoinHostPort(dstAddr, fmt.Sprintf("%d", dstPort))
	logger.Println("CONN", oldTarget, "->", policy)
	if policy.Mode == "block" {
		sendReply(logger, clientConn, 0x02)
		return
	}
	if policy.Port != nil && *policy.Port != 0 {
		dstPort = *policy.Port
	}
	target := net.JoinHostPort(dstHost, fmt.Sprintf("%d", dstPort))

	var dstConn net.Conn
	replyFirst := policy.ReplyFirst != nil && *policy.ReplyFirst
	if replyFirst {
		sendReply(logger, clientConn, 0x00)
	} else {
		dstConn, err = net.Dial("tcp", target)
		if err != nil {
			logger.Println("Connection failed:", err)
			sendReply(logger, clientConn, 0x01)
			return
		}
		sendReply(logger, clientConn, 0x00)
		defer dstConn.Close()
	}

	if policy.Mode == "raw" {
		if replyFirst {
			dstConn, err = net.Dial("tcp", target)
			if err != nil {
				logger.Println("Connection failed:", err)
				return
			}
			defer dstConn.Close()
		}
		go io.Copy(clientConn, dstConn)
		io.Copy(dstConn, clientConn)
		return
	}

	br := bufio.NewReader(clientConn)
	peekBytes, err := br.Peek(5)
	if err != nil {
		if errors.Is(err, io.EOF) {
			logger.Println("Empty tunnel")
		} else {
			logger.Println("Read first packet fail:", err)
		}
		return
	}
	switch peekBytes[0] {
	case 'G', 'P', 'D', 'O', 'T', 'H':
		req, err := http.ReadRequest(br)
		if err != nil {
			logger.Println("HTTP request parsing fail:", err)
			return
		}
		defer req.Body.Close()

		host := req.Host
		if host == "" {
			host = req.URL.Host
			if host == "" {
				logger.Println("Cannot determine target host")
				return
			}
		}
		logger.Printf("%s %s to %s", req.Method, req.URL, host)

		policy := domainMatcher.Find(host)
		if policy == nil {
			policy = &defaultPolicy
		} else {
			policy = mergePolicies(defaultPolicy, *policy)
		}
		if policy.Host != nil && *policy.Host != "" {
			if (*policy.Host)[0] != '^' {
				_, ipPolicy, err := ipRedirect(logger, *policy.Host)
				if err != nil {
					logger.Println("IP redirect error:", err)
					return
				}
				policy = mergePolicies(defaultPolicy, *ipPolicy, *policy)
			}
		}
		if policy.HttpStatus == 0 {
			if replyFirst {
				dstConn, err = net.Dial("tcp", target)
				if err != nil {
					logger.Println("Connection failed:", err)
					resp := &http.Response{
						Status:        "502 Bad Gateway",
						StatusCode:    502,
						Proto:         req.Proto,
						ProtoMajor:    1,
						ProtoMinor:    1,
						Header:        make(http.Header),
						ContentLength: 0,
						Close:         true,
					}
					if err = resp.Write(clientConn); err != nil {
						logger.Println("Send 502 fail:", err)
					}
					return
				}
				defer dstConn.Close()
			}
			if err := req.Write(dstConn); err != nil {
				logger.Println("Forward req fail:", err)
				return
			}
		} else {
			statusLine := fmt.Sprintf("%d %s", policy.HttpStatus, http.StatusText(policy.HttpStatus))
			resp := &http.Response{
				Status:        statusLine,
				StatusCode:    policy.HttpStatus,
				Proto:         req.Proto,
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        make(http.Header),
				ContentLength: 0,
				Close:         true,
			}
			if policy.HttpStatus == 301 || policy.HttpStatus == 302 {
				resp.Header.Set("Location", "https://"+host+req.URL.RequestURI())
			}
			if err = resp.Write(clientConn); err != nil {
				logger.Printf("Send %d fail: %s", policy.HttpStatus, err)
			} else {
				logger.Println("Sent", statusLine)
			}
			return
		}
	case 0x16:
		payloadLen := binary.BigEndian.Uint16(peekBytes[3:5])
		record := make([]byte, 5+payloadLen)
		if _, err = io.ReadFull(br, record); err != nil {
			logger.Println("Read first record fail:", err)
			return
		}
		prtVer, sniPos, sniLen, hasKeyShare, err := parseClientHello(record)
		if err != nil {
			logger.Println("Record parsing fail:", err)
			return
		}
		if policy.Mode == "tls-alert" {
			// fatal access_denied
			if err = sendTLSAlert(clientConn, prtVer, 49, 2); err != nil {
				logger.Println("Send TLS alert fail:", err)
			}
			return
		}
		if policy.TLS13Only != nil && *policy.TLS13Only && !hasKeyShare {
			logger.Println("Not a TLS 1.3 ClientHello, connection blocked")
			// fatal protocol_version
			if err = sendTLSAlert(clientConn, prtVer, 70, 2); err != nil {
				logger.Println("Send TLS alert fail:", err)
			}
			return
		}
		if sniPos <= 0 || sniLen <= 0 {
			logger.Println("SNI not found")
			if replyFirst {
				dstConn, err = net.Dial("tcp", target)
				if err != nil {
					logger.Println("Connection failed:", err)
					return
				}
				defer dstConn.Close()
			}
			if _, err = dstConn.Write(record); err != nil {
				logger.Println("Send ClientHello directly fail:", err)
				return
			}
			logger.Println("Sent ClientHello directly")
		} else {
			sniStr := string(record[sniPos : sniPos+sniLen])
			if dstAddr != sniStr {
				logger.Println("Server name:", sniStr)
				domainPolicy := domainMatcher.Find(sniStr)
				if domainPolicy == nil {
					domainPolicy = &defaultPolicy
				} else {
					domainPolicy = mergePolicies(defaultPolicy, *domainPolicy)
				}
				switch domainPolicy.Mode {
				case "block":
					return
				case "tls-alert":
					if err = sendTLSAlert(clientConn, prtVer, 49, 2); err != nil {
						logger.Println("Send TLS alert fail:", err)
					}
					return
				}
			}

			if replyFirst {
				dstConn, err = net.Dial("tcp", target)
				if err != nil {
					logger.Println("Connection failed:", err)
					return
				}
				defer dstConn.Close()
			}
			switch policy.Mode {
			case "direct":
				if _, err = dstConn.Write(record); err != nil {
					logger.Println("Send ClientHello directly fail:", err)
					return
				}
				logger.Println("Sent ClientHello directly")
			case "tls-rf":
				err = sendRecords(dstConn, record, sniPos, sniLen, policy.NumRecords, policy.NumSegments)
				if err != nil {
					logger.Println("TLS fragmentation fail:", err)
					return
				}
				logger.Println("Successfully sent ClientHello")
			case "ttl-d":
				var ttl int
				ipv6 := target[0] == '['
				if policy.FakeTTL == 0 {
					ttl, err = minReachableTTL(target, ipv6)
					if err != nil {
						logger.Println("TTL probing fail:", err)
						sendReply(logger, clientConn, 0x01)
						return
					}
					if ttl == -1 {
						logger.Println("Reachable TTL not found")
						sendReply(logger, clientConn, 0x01)
						return
					}
					if calcTTL != nil {
						ttl, err = calcTTL(ttl)
						if err != nil {
							logger.Println("TTL calculating fail:", err)
							sendReply(logger, clientConn, 0x01)
							return
						}
					} else {
						ttl -= 1
					}
					logger.Printf("fake_ttl=%d", ttl)
				} else {
					ttl = policy.FakeTTL
				}
				err = desyncSend(
					dstConn, ipv6, record, fakePacket,
					sniPos, sniLen, ttl, policy.FakeSleep,
				)
				if err != nil {
					logger.Println("TTL desync fail:", err)
					return
				}
				logger.Println("Successfully sent ClientHello")
			}
		}
	default:
		logger.Println("Unknown packet type")
		if replyFirst {
			dstConn, err = net.Dial("tcp", target)
			if err != nil {
				logger.Println("Connection failed:", err)
				return
			}
			defer dstConn.Close()
		}
	}

	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			clientConn.Close()
			if dstConn != nil {
				dstConn.Close()
			}
		})
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(dstConn, clientConn)
		closeBoth()
	}()
	go func() {
		defer wg.Done()
		io.Copy(clientConn, dstConn)
		closeBoth()
	}()
	wg.Wait()
}

func main() {
	fmt.Println("moi-si/lumine v0.0.8")
	configPath := flag.String("config", "config.json", "Config file path")
	addr := flag.String("addr", "", "Bind address (default: address from config file)")
	flag.Parse()
	serverAddr, err := loadConfig(*configPath)
	if err != nil {
		fmt.Println("Failed to load config:", err)
		return
	}

	var listenAddr string
	if *addr == "" {
		listenAddr = serverAddr
	} else {
		listenAddr = *addr
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		panic(fmt.Sprintf("Listen error: %s", err))
	}
	fmt.Println("Listening on", listenAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Error accept: %s", err)
		} else {
			go handleClient(conn)
		}
	}
}

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

func sendReply(logger *log.Logger, conn net.Conn, rep byte, bindIP net.IP, bindPort uint16) {
	if bindIP == nil {
		bindIP = net.IPv4zero
	}
	resp := []byte{0x05, rep, 0x00, 0x01}
	resp = append(resp, bindIP.To4()...)
	portBytes := make([]byte, 2)
	binary.BigEndian.AppendUint16(portBytes, bindPort)
	resp = append(resp, portBytes...)
	if _, err := conn.Write(resp); err != nil {
		logger.Println("ERROR send SOCKS5 reply:", err)
	}
}

func handleClient(clientConn net.Conn) {
	defer clientConn.Close()
	logger := makeLogger()
	logger.Println("Accepted connection from", clientConn.RemoteAddr().String())

	header, err := readN(clientConn, 2)
	if err != nil {
		logger.Println("ERROR read method selection message:", err)
		return
	}
	if header[0] != 0x05 {
		logger.Println("Not SOCKS5:", header[0])
		return
	}
	nMethods := int(header[1])
	methods, err := readN(clientConn, nMethods)
	if err != nil {
		logger.Println("ERROR read methods:", err)
		return
	}
	var authMethod byte = 0xFF // No acceptable methods
	if slices.Contains(methods, 0x00) {
		authMethod = 0x00
	}
	if _, err = clientConn.Write([]byte{0x05, authMethod}); err != nil {
		logger.Println("ERROR read auth method:", err)
		return
	}
	if authMethod == 0xFF {
		logger.Println("No `no auth` method was given")
		return
	}

	header, err = readN(clientConn, 4)
	if err != nil {
		logger.Println("ERROR read request header:", err)
		return
	}
	if header[0] != 0x05 {
		logger.Println("Invalid version:", header[0])
		return
	}
	if header[1] != 0x01 {
		logger.Println("Not CONNECT:", header[1])
		sendReply(logger, clientConn, 0x07, nil, 0)
		return
	}

	var dstAddr, dstHost string
	var policy *Policy
	switch header[3] {
	case 0x01: // IPv4 address
		ipBytes, err := readN(clientConn, 4)
		if err != nil {
			logger.Println("ERROR read IPv4 dest address:", err)
			return
		}
		dstAddr = net.IP(ipBytes).String()
		var ipPolicy *Policy
		dstHost, ipPolicy = ipRedirect(logger, dstAddr)
		if ipPolicy == nil {
			policy = &defaultPolicy
		} else {
			policy = mergePolicies(defaultPolicy, *ipPolicy)
		}
	case 0x04: // IPv6 address
		ipBytes, err := readN(clientConn, 16)
		if err != nil {
			logger.Println("ERROR read IPv6 dest address:", err)
			return
		}
		dstAddr = net.IP(ipBytes).String()
		var ipPolicy *Policy
		dstHost, ipPolicy = ipRedirect(logger, dstAddr)
		if ipPolicy == nil {
			policy = &defaultPolicy
		} else {
			policy = mergePolicies(defaultPolicy, *ipPolicy)
		}
	case 0x03: // Domain name
		lenByte, err := readN(clientConn, 1)
		if err != nil {
			logger.Println("ERROR read domain length:", err)
			return
		}
		domainBytes, err := readN(clientConn, int(lenByte[0]))
		if err != nil {
			logger.Println("ERROR read domain:", err)
			return
		}
		dstAddr = string(domainBytes)
		// For Firefox
		if net.ParseIP(dstAddr) != nil {
			var ipPolicy *Policy
			dstHost, ipPolicy = ipRedirect(logger, dstAddr)
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
						logger.Printf("ERROR resolve %s: err1=%s; err2=%s", dstAddr, err1, err2)
						sendReply(logger, clientConn, 0x01, nil, 0)
						return
					}
				} else {
					var err error
					dstHost, err = dnsQuery(dstAddr, first)
					if err != nil {
						logger.Printf("ERROR resolve %s: %s", dstAddr, err)
						sendReply(logger, clientConn, 0x01, nil, 0)
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
				dstHost, ipPolicy = ipRedirect(logger, dstHost)
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
		sendReply(logger, clientConn, 0x08, nil, 0)
		return
	}
	portBytes, err := readN(clientConn, 2)
	if err != nil {
		logger.Println("ERROR read port:", err)
		return
	}
	dstPort := binary.BigEndian.Uint16(portBytes)
	oldTarget := net.JoinHostPort(dstAddr, fmt.Sprintf("%d", dstPort))
	logger.Printf("CONNECT %s -> %s", oldTarget, policy)
	if policy.Mode == "block" {
		logger.Println("Connection blocked")
		sendReply(logger, clientConn, 0x02, nil, 0)
		return
	}
	if policy.Port != nil && *policy.Port != 0 {
		dstPort = *policy.Port
	}
	target := net.JoinHostPort(dstHost, fmt.Sprintf("%d", dstPort))

	var dstConn net.Conn
	replyFirst := policy.ReplyFirst != nil && *policy.ReplyFirst
	if replyFirst {
		sendReply(logger, clientConn, 0x00, nil, 0)
	} else {
		dstConn, err = net.Dial("tcp", target)
		if err != nil {
			logger.Println("Connection failed:", err)
			sendReply(logger, clientConn, 0x01, nil, 0)
			return
		}
		sendReply(logger, clientConn, 0x00, nil, 0)
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
			logger.Println("Client sent nothing in tunnel")
		} else {
			logger.Println("ERROR read first packet:", err)
		}
		return
	}
	switch peekBytes[0] {
	case 'G', 'P', 'D', 'O', 'T', 'H':
		req, err := http.ReadRequest(br)
		if err != nil {
			logger.Println("ERROR parse HTTP request:", err)
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
				_, ipPolicy := ipRedirect(logger, *policy.Host)
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
						logger.Println("ERROR send 502 response:", err)
					}
					return
				}
				defer dstConn.Close()
			}
			if err := req.Write(dstConn); err != nil {
				logger.Println("ERROR forward request:", err)
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
				logger.Printf("ERROR send %d response: %s", policy.HttpStatus, err)
			} else {
				logger.Println("Sent", statusLine)
			}
			return
		}
	case 0x16:
		payloadLen := binary.BigEndian.Uint16(peekBytes[3:5])
		record := make([]byte, 5+payloadLen)
		if _, err = io.ReadFull(br, record); err != nil {
			logger.Println("ERROR read first record:", err)
			return
		}
		prtVer, sniPos, sniLen, hasKeyShare, err := parseClientHello(record)
		if err != nil {
			logger.Println("ERROR parse record:", err)
			return
		}
		if policy.Mode == "tls-alert" {
			// fatal access_denied
			if err = sendTLSAlert(clientConn, prtVer, 49, 2); err != nil {
				logger.Println("ERROR send TLS Alert:", err)
			}
			return
		}
		if policy.TLS13Only != nil && *policy.TLS13Only && !hasKeyShare {
			logger.Println("Not a TLS 1.3 ClientHello, connection blocked")
			// fatal protocol_version
			if err = sendTLSAlert(clientConn, prtVer, 70, 2); err != nil {
				logger.Println("ERROR send TLS Alert:", err)
			}
			return
		}
		if sniPos <= 0 || sniLen <= 0 {
			logger.Println("No SNI in ClientHello")
			if replyFirst {
				dstConn, err = net.Dial("tcp", target)
				if err != nil {
					logger.Println("Connection failed:", err)
					return
				}
				defer dstConn.Close()
			}
			if _, err = dstConn.Write(record); err != nil {
				logger.Println("ERROR send ClientHello directly:", err)
				return
			}
			logger.Println("Sent ClientHello directly")
		} else {
			sniStr := string(record[sniPos : sniPos+sniLen])
			logger.Println("Server name:", sniStr)
			if dstAddr != sniStr {
				domainPolicy := domainMatcher.Find(sniStr)
				if domainPolicy == nil {
					domainPolicy = &defaultPolicy
				} else {
					domainPolicy = mergePolicies(defaultPolicy, *domainPolicy)
				}
				if domainPolicy.Mode == "block" {
					logger.Println("Connection blocked")
					return
				}
				if domainPolicy.Mode == "tls-alert" {
					if err = sendTLSAlert(clientConn, prtVer, 49, 2); err != nil {
						logger.Println("ERROR send TLS Alert:", err)
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
					logger.Println("ERROR send ClientHello directly:", err)
					return
				}
				logger.Println("Sent ClientHello directly")
			case "tls-rf":
				err = sendRecords(dstConn, record, sniPos, sniLen, policy.NumRecords)
				if err != nil {
					logger.Println("ERROR TLS fragmentation:", err)
					return
				}
				logger.Println("Successfully sent ClientHello")
			case "ttl-d":
				fakePacketBytes, err := encode(policy.FakePacket)
				if err != nil {
					logger.Println("ERROR encode fake packet:", err)
					return
				}
				var ttl int
				ipv6 := target[0] == '['
				if policy.FakeTTL == 0 {
					ttl, err = minReachableTTL(target, ipv6)
					if err != nil {
						logger.Println("Probe TTL failed:", err)
						sendReply(logger, clientConn, 0x01, nil, 0)
						return
					}
					if ttl == -1 {
						logger.Println("Reachable TTL not found")
						sendReply(logger, clientConn, 0x01, nil, 0)
						return
					}
					if calcTTL != nil {
						ttl, err = calcTTL(ttl)
						if err != nil {
							logger.Println("ERROR calculate TTL:", err)
							sendReply(logger, clientConn, 0x01, nil, 0)
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
					dstConn, ipv6, record, fakePacketBytes,
					sniPos, sniLen, ttl, policy.FakeSleep,
				)
				if err != nil {
					logger.Println("ERROR TTL desync:", err)
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

	go io.Copy(clientConn, dstConn)
	io.Copy(dstConn, clientConn)
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

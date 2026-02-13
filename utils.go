package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"

	log "github.com/moi-si/mylog"
	"github.com/cespare/xxhash/v2"
)

func parseClientHello(data []byte) (prtVer []byte, sniPos int, sniLen int, hasKeyShare bool, err error) {
	const (
		recordHeaderLen          = 5
		handshakeHeaderLen       = 4
		handshakeTypeClientHello = 0x01
		extTypeSNI               = 0x0000
		extTypeKeyShare          = 0x0033
	)

	prtVer = nil
	sniPos = -1
	sniLen = 0

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < recordHeaderLen+recordLen {
		return prtVer, sniPos, sniLen, false, errors.New("record length exceeds data size")
	}
	offset := recordHeaderLen

	if recordLen < handshakeHeaderLen {
		return prtVer, sniPos, sniLen, false, errors.New("handshake message too short")
	}
	if data[offset] != handshakeTypeClientHello {
		return prtVer, sniPos, sniLen, false, fmt.Errorf("not a ClientHello handshake (type=%d)", data[offset])
	}
	handshakeLen := int(uint32(data[offset+1])<<16 | uint32(data[offset+2])<<8 | uint32(data[offset+3]))
	if handshakeLen+handshakeHeaderLen > recordLen {
		return prtVer, sniPos, sniLen, false, errors.New("handshake length exceeds record length")
	}
	offset += handshakeHeaderLen

	if handshakeLen < 2+32+1 {
		return prtVer, sniPos, sniLen, false, errors.New("ClientHello too short for mandatory fields")
	}
	prtVer = data[offset : offset+2]
	offset += 2
	offset += 32
	if offset >= len(data) {
		return prtVer, sniPos, sniLen, false, errors.New("unexpected end after Random")
	}
	sessionIDLen := int(data[offset])
	offset++
	if offset+sessionIDLen > len(data) {
		return prtVer, sniPos, sniLen, false, errors.New("session_id length exceeds data")
	}
	offset += sessionIDLen

	if offset+2 > len(data) {
		return prtVer, sniPos, sniLen, false, errors.New("cannot read cipher_suites length")
	}
	csLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+csLen > len(data) {
		return prtVer, sniPos, sniLen, false, errors.New("cipher_suites exceed data")
	}
	offset += csLen

	if offset >= len(data) {
		return prtVer, sniPos, sniLen, false, errors.New("cannot read compression_methods length")
	}
	compMethodsLen := int(data[offset])
	offset++
	if offset+compMethodsLen > len(data) {
		return prtVer, sniPos, sniLen, false, errors.New("compression_methods exceed data")
	}
	offset += compMethodsLen

	// Extensions
	if offset+2 > len(data) {
		return prtVer, sniPos, sniLen, false, nil
	}
	extTotalLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+extTotalLen > len(data) {
		return prtVer, sniPos, sniLen, false, errors.New("extensions length exceeds data")
	}
	extensionsEnd := offset + extTotalLen

	for offset+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		extDataStart := offset + 4
		extDataEnd := extDataStart + extLen

		if extDataEnd > extensionsEnd {
			return prtVer, sniPos, sniLen, false, errors.New("extension length exceeds extensions block")
		}

		if extType == extTypeKeyShare {
			hasKeyShare = true
			if sniPos != -1 {
				return prtVer, sniPos, sniLen, hasKeyShare, nil
			}
		}

		if sniPos == -1 && extType == extTypeSNI {
			if extLen < 2 {
				return prtVer, sniPos, sniLen, hasKeyShare, errors.New("malformed SNI extension (too short for list length)")
			}
			listLen := int(binary.BigEndian.Uint16(data[extDataStart : extDataStart+2]))
			if listLen+2 != extLen {
				return prtVer, sniPos, sniLen, hasKeyShare, errors.New("SNI list length field mismatch")
			}
			cursor := extDataStart + 2
			if cursor+3 > extDataEnd {
				return prtVer, sniPos, sniLen, hasKeyShare, errors.New("SNI entry too short")
			}
			nameType := data[cursor]
			if nameType != 0 {
				return prtVer, sniPos, sniLen, hasKeyShare, errors.New("unsupported SNI name type")
			}
			nameLen := int(binary.BigEndian.Uint16(data[cursor+1 : cursor+3]))
			nameStart := cursor + 3
			nameEnd := nameStart + nameLen
			if nameEnd > extDataEnd {
				return prtVer, sniPos, sniLen, hasKeyShare, errors.New("SNI name length exceeds extension")
			}
			sniPos = nameStart
			sniLen = nameLen
			if hasKeyShare {
				return prtVer, sniPos, sniLen, hasKeyShare, nil
			}
		}
		offset = extDataEnd
	}
	return prtVer, sniPos, sniLen, hasKeyShare, nil
}

func sendTLSAlert(conn net.Conn, prtVer []byte, desc byte, level byte) error {
	_, err := conn.Write([]byte{0x15, prtVer[0], prtVer[1], 0x00, 0x02, level, desc})
	return err
}

func expandPattern(s string) []string {
	left := -1
	right := -1
	for i, ch := range s {
		if ch == '(' && left == -1 {
			left = i
		}
		if ch == ')' && right == -1 {
			right = i
		}
	}
	if left == -1 && right == -1 {
		return splitByPipe(s)
	}

	prefix := s[:left]
	suffix := s[right+1:]
	inner := s[left+1 : right]

	parts := splitByPipe(inner)
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		result = append(result, prefix+part+suffix)
	}
	return result
}

func splitByPipe(s string) []string {
	if s == "" {
		return []string{""}
	}
	result := []string{}
	curr := ""
	for _, ch := range s {
		if ch == '|' {
			result = append(result, curr)
			curr = ""
		} else {
			curr += string(ch)
		}
	}
	result = append(result, curr)
	return result
}

func transformIP(ipStr string, targetNetStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", errors.New("invalid IP")
	}
	_, targetNet, err := net.ParseCIDR(targetNetStr)
	if err != nil {
		return "", fmt.Errorf("invalid target network: %w", err)
	}

	isIPv4 := ip.To4() != nil
	isIPv4Target := targetNet.IP.To4() != nil
	if (isIPv4 && !isIPv4Target) || (!isIPv4 && isIPv4Target) {
		return "", errors.New("IP version mismatch between source IP and target network")
	}

	var maxLen int
	if isIPv4 {
		maxLen = 32
	} else {
		maxLen = 128
	}

	prefixLen, _ := targetNet.Mask.Size()

	hostBits := maxLen - prefixLen

	fullMask := new(big.Int).Sub(
		new(big.Int).Lsh(big.NewInt(1), uint(maxLen)),
		big.NewInt(1),
	)

	hostMask := new(big.Int).Sub(
		new(big.Int).Lsh(big.NewInt(1), uint(hostBits)),
		big.NewInt(1),
	)
	networkMask := new(big.Int).Xor(fullMask, hostMask)
	toBigInt := func(ip net.IP) *big.Int {
		if isIPv4 {
			ip = ip.To4()
		} else {
			ip = ip.To16()
		}
		return new(big.Int).SetBytes(ip)
	}

	ipInt := toBigInt(ip)
	netInt := toBigInt(targetNet.IP)

	newIPInt := new(big.Int).Or(
		new(big.Int).And(netInt, networkMask),
		new(big.Int).And(ipInt, hostMask),
	)

	expectedLen := 4
	if !isIPv4 {
		expectedLen = 16
	}
	newIPBytes := newIPInt.Bytes()
	if len(newIPBytes) < expectedLen {
		padded := make([]byte, expectedLen)
		copy(padded[expectedLen-len(newIPBytes):], newIPBytes)
		newIPBytes = padded
	}

	return net.IP(newIPBytes).String(), nil
}

func ipRedirect(logger *log.Logger, ip string) (string, *Policy, error) {
	for range maxJump {
		policy := getIPPolicy(ip)
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
		if strings.LastIndexByte(mapTo, '/') != -1 {
			var err error
			mapTo, err = transformIP(ip, mapTo)
			if err != nil {
				return "", nil, err
			}
		}
		if ip == mapTo {
			return ip, policy, nil
		}
		logger.Info("Redirect:", ip, "->", mapTo)

		if chain {
			ip = mapTo
			continue
		}
		return mapTo, getIPPolicy(mapTo), nil
	}
	return "", nil, errors.New("too many redirects")
}

func handleTunnel(
	p Policy, replyFirst bool, dstConn, cliConn net.Conn, logger *log.Logger,
	target, originHost string, closeBoth func()) {
	var err error

	if p.Mode == ModeRaw {
		if replyFirst {
			dstConn, err = net.DialTimeout("tcp", target, p.ConnectTimeout)
			if err != nil {
				logger.Error("Connection failed:", err)
				return
			}
		}
		go func() {
			if _, err := io.Copy(dstConn, cliConn); err != nil && !isUseOfClosedConn(err) {
				logger.Error("Copy dest -> client:", err)
			}
			closeBoth()
		}()
		if _, err := io.Copy(cliConn, dstConn); err != nil && !isUseOfClosedConn(err) {
			logger.Error("Copy client -> dest:", err)
		}
		closeBoth()
		return
	}

	br := bufio.NewReader(cliConn)
	peekBytes, err := br.Peek(5)
	if err != nil {
		if len(peekBytes) == 0 && errors.Is(err, io.EOF) {
			logger.Error("Empty tunnel")
		} else {
			logger.Error("Read first packet:", err)
		}
		return
	}
	switch peekBytes[0] {
	case 'G', 'P', 'D', 'O', 'T', 'H':
		req, err := http.ReadRequest(br)
		if err != nil {
			logger.Error("Parse HTTP request:", err)
			return
		}
		defer req.Body.Close()

		host := req.Host
		if host == "" {
			host = req.URL.Host
			if host == "" {
				logger.Error("Cannot determine target host")
				return
			}
		}
		logger.Info(req.Method, req.URL, "to", host)

		var policy Policy
		domainPolicy := domainMatcher.Find(host)
		if domainPolicy == nil {
			policy = defaultPolicy
		} else {
			policy = mergePolicies(&policy, &defaultPolicy)
		}
		if policy.Host != nil && *policy.Host != "" {
			if (*p.Host)[0] != '^' {
				_, ipPolicy, err := ipRedirect(logger, *p.Host)
				if err != nil {
					logger.Error("IP redirect:", err)
					return
				}
				if ipPolicy != nil {
					policy = mergePolicies(&policy, ipPolicy, &defaultPolicy)
				}
			}
		}
		if p.HttpStatus == 0 || p.HttpStatus == -1 {
			if replyFirst {
				dstConn, err = net.DialTimeout("tcp", target, p.ConnectTimeout)
				if err != nil {
					logger.Error("Connection failed:", err)
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
					if err = resp.Write(cliConn); err != nil {
						logger.Debug("Send 502:", err)
					}
					return
				}
			}
			if err := req.Write(dstConn); err != nil {
				logger.Error("Forward request:", err)
				return
			}
		} else {
			statusLine := strconv.Itoa(p.HttpStatus) + " " + http.StatusText(p.HttpStatus)
			resp := &http.Response{
				Status:        statusLine,
				StatusCode:    p.HttpStatus,
				Proto:         req.Proto,
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        make(http.Header),
				ContentLength: 0,
				Close:         true,
			}
			if p.HttpStatus == 301 || p.HttpStatus == 302 {
				resp.Header.Set("Location", "https://"+host+req.URL.RequestURI())
			}
			if err = resp.Write(cliConn); err != nil {
				logger.Error("Send", p.HttpStatus, "fail:", err)
			} else {
				logger.Info("Sent", statusLine)
			}
			return
		}
	case 0x16:
		payloadLen := binary.BigEndian.Uint16(peekBytes[3:5])
		record := make([]byte, 5+payloadLen)
		if _, err = io.ReadFull(br, record); err != nil {
			logger.Error("Read first record:", err)
			return
		}
		prtVer, sniPos, sniLen, hasKeyShare, err := parseClientHello(record)
		if err != nil {
			logger.Error("Parse record:", err)
			return
		}
		if p.Mode == ModeTLSAlert {
			// fatal access_denied
			if err = sendTLSAlert(cliConn, prtVer, 49, 2); err != nil {
				logger.Debug("Send TLS alert:", err)
			}
			return
		}
		if p.TLS13Only == BoolTrue && !hasKeyShare {
			logger.Info("Not a TLS 1.3 ClientHello, connection blocked")
			// fatal protocol_version
			if err = sendTLSAlert(cliConn, prtVer, 70, 2); err != nil {
				logger.Debug("Send TLS alert:", err)
			}
			return
		}
		if sniPos <= 0 || sniLen <= 0 {
			logger.Info("SNI not found")
			if replyFirst {
				dstConn, err = net.DialTimeout("tcp", target, p.ConnectTimeout)
				if err != nil {
					logger.Error("Connection failed:", err)
					return
				}
			}
			if _, err = dstConn.Write(record); err != nil {
				logger.Error("ClientHello sending directly:", err)
				return
			}
			logger.Info("ClientHello sent directly")
		} else {
			sniStr := string(record[sniPos : sniPos+sniLen])
			if originHost != sniStr {
				logger.Info("Server name:", sniStr)
				var sniPolicy Policy
				domainPolicy := domainMatcher.Find(sniStr)
				if domainPolicy == nil {
					sniPolicy = defaultPolicy
				} else {
					sniPolicy = mergePolicies(domainPolicy, &defaultPolicy)
				}
				switch sniPolicy.Mode {
				case ModeBlock:
					logger.Info("Connection blocked")
					return
				case ModeTLSAlert:
					if err = sendTLSAlert(cliConn, prtVer, 49, 2); err != nil {
						logger.Error("Send TLS alert:", err)
					}
					logger.Info("Connection blocked by sending TLS alert")
					return
				}
			}

			if replyFirst {
				dstConn, err = net.DialTimeout("tcp", target, p.ConnectTimeout)
				if err != nil {
					logger.Error("Connection failed:", err)
					return
				}
			}
			switch p.Mode {
			case ModeDirect:
				if _, err = dstConn.Write(record); err != nil {
					logger.Error("ClientHello sending directly:", err)
					return
				}
				logger.Info("ClientHello sent directly")
			case ModeTLSRF:
				err = sendRecords(dstConn, record, sniPos, sniLen,
					p.NumRecords, p.NumSegments,
					p.OOB == BoolTrue, p.ModMinorVer == BoolTrue,
					p.SendInterval)
				if err != nil {
					logger.Error("TLSRF fail:", err)
					return
				}
				logger.Info("ClientHello sent")
			case ModeTTLD:
				var ttl int
				ipv6 := target[0] == '['
				if p.FakeTTL == 0 || p.FakeTTL == -1 {
					var cached bool
					ttl, cached, err = minReachableTTL(target, ipv6, p.MaxTTL, p.Attempts, p.SingleTimeout)
					if err != nil {
						logger.Error("Probe TTL:", err)
						return
					}
					if ttl == -1 {
						logger.Error("Reachable TTL not found")
						return
					}
					if calcTTL != nil {
						ttl, err = calcTTL(ttl)
						if err != nil {
							logger.Error("Calculate TTL:", err)
							return
						}
					} else {
						ttl -= 1
					}
					if cached {
						logger.Info("Fake TTL(cache): ", strconv.Itoa(ttl))
					} else {
						logger.Info("Fake TTL:", ttl)
					}
				} else {
					ttl = p.FakeTTL
				}
				err = desyncSend(
					dstConn, ipv6, record,
					sniPos, sniLen, ttl, p.FakeSleep,
				)
				if err != nil {
					logger.Error("TTLD fail:", err)
					return
				}
				logger.Info("ClientHello sent")
			}
		}
	default:
		logger.Info("Unknown packet type")
		if replyFirst {
			dstConn, err = net.DialTimeout("tcp", target, p.ConnectTimeout)
			if err != nil {
				logger.Error("Connection failed:", err)
				return
			}
		}
	}

	go func() {
		if _, err := io.Copy(dstConn, cliConn); err != nil && !isUseOfClosedConn(err) {
			logger.Error("Copy dest -> client:", err)
		}
		closeBoth()
	}()
	if _, err := io.Copy(cliConn, dstConn); err != nil && !isUseOfClosedConn(err) {
		logger.Error("Copy client -> dest:", err)
	}
	closeBoth()
}

func genPolicy(logger *log.Logger, originHost string) (dstHost string, p Policy, fail bool, block bool) {
	var err error

	if net.ParseIP(originHost) != nil {
		var ipPolicy *Policy
		dstHost, ipPolicy, err = ipRedirect(logger, originHost)
		if err != nil {
			logger.Error("IP redirect:", err)
			return "", Policy{}, true, false
		}
		if ipPolicy == nil {
			p = defaultPolicy
		} else {
			p = mergePolicies(ipPolicy, &defaultPolicy)
		}
		if p.Mode == ModeBlock {
			return "", Policy{}, false, true
		}
	} else {
		domainPolicy := domainMatcher.Find(originHost)
		found := domainPolicy != nil
		if found {
			if domainPolicy.Mode == ModeBlock {
				return "", Policy{}, false, true
			}
			p = mergePolicies(domainPolicy, &defaultPolicy)
		} else {
			p = defaultPolicy
		}
		var disableRedirect, cached bool
		if p.Host == nil || *p.Host == "" {
			dstHost, cached, err = dnsResolve(originHost, p.DNSMode)
			if err != nil {
				logger.Error("Resolve", originHost+":", err)
				return "", Policy{}, true, false
			}
			if cached {
				logger.Info("DNS(cached):", originHost, "->", dstHost)
			} else {
				logger.Info("DNS:", originHost, "->", dstHost)
			}
		} else {
			disableRedirect = (*p.Host)[0] == '^'
			if disableRedirect {
				dstHost = (*p.Host)[1:]
			} else {
				dstHost = *p.Host
			}
		}
		if !disableRedirect {
			var ipPolicy *Policy
			dstHost, ipPolicy, err = ipRedirect(logger, dstHost)
			if err != nil {
				logger.Info("IP redirect:", err)
				return "", Policy{}, true, false
			}
			if ipPolicy != nil {
				if found {
					p = mergePolicies(domainPolicy, ipPolicy, &defaultPolicy)
				} else {
					p = mergePolicies(ipPolicy, &defaultPolicy)
				}
				if p.Mode == ModeBlock {
					return "", Policy{}, false, true
				}
			}
		}
	}
	return
}

func getRawConn(conn net.Conn) (syscall.RawConn, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, errors.New("not *net.TCPConn")
	}
	return tcpConn.SyscallConn()
}

func findLastDot(data []byte, sniPos, sniLen int) (offset int, found bool) {
	for i := sniPos + sniLen; i >= sniPos; i-- {
		if data[i] == '.' {
			return i, true
		}
	}
	return sniLen/2 + sniPos, false
}

func isUseOfClosedConn(err error) bool {
	return strings.Contains(err.Error(), "use of closed")
}

func hashStringXXHASH(s string) uint32 {
	return uint32(xxhash.Sum64String(s))
}
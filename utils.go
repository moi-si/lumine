package main

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
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
		return "", fmt.Errorf("invalid target network: %v", err)
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

var (
	dnsClient       *dns.Client
	httpCli         *http.Client
	dnsQuery        func(string, uint16) (string, error)
	dnsCacheEnabled bool
	dnsCache        sync.Map
	dnsCacheTTL     int
)

type dnsCacheValue struct {
	IP       string
	ExpireAt time.Time
}

func do53Query(domain string, qtype uint16) (string, error) {
	if dnsCacheEnabled {
		v, ok := ttlCache.Load(domain)
		if ok {
			k := v.(dnsCacheValue)
			if !k.ExpireAt.IsZero() {
				if time.Now().Before(k.ExpireAt) {
					return k.IP, nil
				} else {
					ttlCache.Delete(domain)
				}
			}
		}
	}

	msg := new(dns.Msg)
	msg.SetQuestion(domain+".", qtype)
	resp, _, err := dnsClient.Exchange(msg, dnsAddr)
	if err != nil {
		return "", fmt.Errorf("dns exchange: %s", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return "", fmt.Errorf("bad rcode: %s", dns.RcodeToString[resp.Rcode])
	}

	var ip string
loop:
	for _, ans := range resp.Answer {
		switch qtype {
		case dns.TypeA:
			if record, ok := ans.(*dns.A); ok {
				ip = record.A.String()
				break loop
			}
		case dns.TypeAAAA:
			if record, ok := ans.(*dns.AAAA); ok {
				ip = record.AAAA.String()
				break loop
			}
		}
	}
	if ip == "" {
		return "", errors.New("record not found")
	} else {
		if dnsCacheEnabled {
			var expireAt time.Time
			if dnsCacheTTL == -1 {
				expireAt = time.Time{}
			} else {
				expireAt = time.Now().Add(time.Duration(dnsCacheTTL * int(time.Second)))
			}
			dnsCache.Store(domain, dnsCacheValue{
				IP:       ip,
				ExpireAt: expireAt,
			})
		}
		return ip, nil
	}
}

func dohQuery(domain string, qtype uint16) (string, error) {
	if dnsCacheEnabled {
		v, ok := ttlCache.Load(domain)
		if ok {
			k := v.(dnsCacheValue)
			if !k.ExpireAt.IsZero() {
				if time.Now().Before(k.ExpireAt) {
					return k.IP, nil
				} else {
					ttlCache.Delete(domain)
				}
			}
		}
	}

	msg := new(dns.Msg)
	msg.SetQuestion(domain+".", qtype)
	wire, err := msg.Pack()
	if err != nil {
		return "", fmt.Errorf("pack dns request: %s", err)
	}
	b64 := base64.RawURLEncoding.EncodeToString(wire)
	u := fmt.Sprintf("%s?dns=%s", dnsAddr, b64)
	httpReq, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", fmt.Errorf("build http request: %s", err)
	}
	httpReq.Header.Set("Accept", "application/dns-message")
	resp, err := httpCli.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("http request: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad http status: %s", resp.Status)
	}
	respWire, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read http body: %s", err)
	}
	ans := new(dns.Msg)
	if err := ans.Unpack(respWire); err != nil {
		return "", fmt.Errorf("unpack dns response: %s", err)
	}
	if ans.Rcode != dns.RcodeSuccess {
		return "", fmt.Errorf("bad rcode: %s", dns.RcodeToString[ans.Rcode])
	}

	var ip string
loop:
	for _, ans := range ans.Answer {
		switch qtype {
		case dns.TypeA:
			if record, ok := ans.(*dns.A); ok {
				ip = record.A.String()
				break loop
			}
		case dns.TypeAAAA:
			if record, ok := ans.(*dns.AAAA); ok {
				ip = record.AAAA.String()
				break loop
			}
		}
	}
	if ip == "" {
		return "", errors.New("record not found")
	} else {
		if dnsCacheEnabled {
			var expireAt time.Time
			if dnsCacheTTL == -1 {
				expireAt = time.Time{}
			} else {
				expireAt = time.Now().Add(time.Duration(dnsCacheTTL * int(time.Second)))
			}
			dnsCache.Store(domain, dnsCacheValue{
				IP:       ip,
				ExpireAt: expireAt,
			})
		}
		return ip, nil
	}
}

func doubleQuery(domain string, first, second uint16) (ip string, err1, err2 error) {
	ip, err1 = dnsQuery(domain, first)
	if err1 != nil {
		ip, err2 = dnsQuery(domain, second)
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

func handleTunnel(
	policy *Policy, replyFirst bool, dstConn, cliConn net.Conn, logger *log.Logger,
	target, originHost string, closeBoth func()) {
	var err error

	if policy.Mode == ModeRaw {
		if replyFirst {
			dstConn, err = net.DialTimeout("tcp", target, policy.ConnectTimeout)
			if err != nil {
				logger.Println("Connection failed:", err)
				return
			}
		}
		done := make(chan struct{}, 2)
		go func() {
			io.Copy(dstConn, cliConn)
			closeBoth()
			done <- struct{}{}
		}()
		go func() {
			io.Copy(cliConn, dstConn)
			closeBoth()
			done <- struct{}{}
		}()
		<-done
		<-done
		return
	}

	br := bufio.NewReader(cliConn)
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
				if ipPolicy != nil {
					policy = mergePolicies(defaultPolicy, *ipPolicy, *policy)
				}
			}
		}
		if policy.HttpStatus == 0 || policy.HttpStatus == -1 {
			if replyFirst {
				dstConn, err = net.DialTimeout("tcp", target, policy.ConnectTimeout)
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
					if err = resp.Write(cliConn); err != nil {
						logger.Println("Send 502 fail:", err)
					}
					return
				}
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
			if err = resp.Write(cliConn); err != nil {
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
		if policy.Mode == ModeTLSAlert {
			// fatal access_denied
			if err = sendTLSAlert(cliConn, prtVer, 49, 2); err != nil {
				logger.Println("Send TLS alert fail:", err)
			}
			return
		}
		if policy.TLS13Only == BoolTrue && !hasKeyShare {
			logger.Println("Not a TLS 1.3 ClientHello, connection blocked")
			// fatal protocol_version
			if err = sendTLSAlert(cliConn, prtVer, 70, 2); err != nil {
				logger.Println("Send TLS alert fail:", err)
			}
			return
		}
		if sniPos <= 0 || sniLen <= 0 {
			logger.Println("SNI not found")
			if replyFirst {
				dstConn, err = net.DialTimeout("tcp", target, policy.ConnectTimeout)
				if err != nil {
					logger.Println("Connection failed:", err)
					return
				}
			}
			if _, err = dstConn.Write(record); err != nil {
				logger.Println("Send ClientHello directly fail:", err)
				return
			}
			logger.Println("Sent ClientHello directly")
		} else {
			sniStr := string(record[sniPos : sniPos+sniLen])
			if originHost != sniStr {
				logger.Println("Server name:", sniStr)
				domainPolicy := domainMatcher.Find(sniStr)
				if domainPolicy == nil {
					domainPolicy = &defaultPolicy
				} else {
					domainPolicy = mergePolicies(defaultPolicy, *domainPolicy)
				}
				switch domainPolicy.Mode {
				case ModeBlock:
					logger.Println("Connection blocked")
					return
				case ModeTLSAlert:
					if err = sendTLSAlert(cliConn, prtVer, 49, 2); err != nil {
						logger.Println("Send TLS alert fail:", err)
					}
					logger.Println("Connection blocked (tls-alert)")
					return
				}
			}

			if replyFirst {
				dstConn, err = net.DialTimeout("tcp", target, policy.ConnectTimeout)
				if err != nil {
					logger.Println("Connection failed:", err)
					return
				}
			}
			switch policy.Mode {
			case ModeDirect:
				if _, err = dstConn.Write(record); err != nil {
					logger.Println("Send ClientHello directly fail:", err)
					return
				}
				logger.Println("Sent ClientHello directly")
			case ModeTLSRF:
				err = sendRecords(dstConn, record, sniPos, sniLen,
					policy.NumRecords, policy.NumSegments,
					policy.OOB == BoolTrue, policy.SendInterval)
				if err != nil {
					logger.Println("TLS fragmentation fail:", err)
					return
				}
				logger.Println("Successfully sent ClientHello")
			case ModeTTLD:
				var ttl int
				ipv6 := target[0] == '['
				if policy.FakeTTL == 0 || policy.FakeTTL == -1 {
					ttl, err = minReachableTTL(target, ipv6)
					if err != nil {
						logger.Println("TTL probing fail:", err)
						sendReply(logger, cliConn, 0x01)
						return
					}
					if ttl == -1 {
						logger.Println("Reachable TTL not found")
						sendReply(logger, cliConn, 0x01)
						return
					}
					if calcTTL != nil {
						ttl, err = calcTTL(ttl)
						if err != nil {
							logger.Println("TTL calculating fail:", err)
							sendReply(logger, cliConn, 0x01)
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
					dstConn, ipv6, record,
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
			dstConn, err = net.DialTimeout("tcp", target, policy.ConnectTimeout)
			if err != nil {
				logger.Println("Connection failed:", err)
				return
			}
		}
	}

	done := make(chan struct{})
	go func() {
		io.Copy(dstConn, cliConn)
		closeBoth()
		done <- struct{}{}
	}()
	go func() {
		io.Copy(cliConn, dstConn)
		closeBoth()
		done <- struct{}{}
	}()
	<-done
	<-done
}

func genPolicy(logger *log.Logger, originHost string) (dstHost string, policy *Policy, fail bool, block bool) {
	var err error

	if net.ParseIP(originHost) != nil {
		var ipPolicy *Policy
		dstHost, ipPolicy, err = ipRedirect(logger, originHost)
		if err != nil {
			logger.Println("IP redirect error:", err)
			return "", nil, true, false
		}
		if ipPolicy == nil {
			policy = &defaultPolicy
		} else {
			policy = mergePolicies(defaultPolicy, *ipPolicy)
		}
		if policy.Mode == ModeBlock {
			return "", nil, false, true
		}
	} else {
		domainPolicy := domainMatcher.Find(originHost)
		found := domainPolicy != nil
		if found {
			policy = mergePolicies(defaultPolicy, *domainPolicy)
		} else {
			policy = &defaultPolicy
		}
		if policy.Mode == ModeBlock {
			return "", nil, false, true
		}
		var disableRedirect bool
		if policy.Host == nil || *policy.Host == "" {
			var first uint16
			if policy.IPv6First == BoolTrue {
				first = dns.TypeAAAA
			} else {
				first = dns.TypeA
			}
			if policy.DNSRetry == BoolTrue {
				var second uint16
				if first == dns.TypeA {
					second = dns.TypeAAAA
				} else {
					second = dns.TypeA
				}
				var err1, err2 error
				dstHost, err1, err2 = doubleQuery(originHost, first, second)
				if err2 != nil {
					logger.Printf("DNS %s fail: %s, %s", originHost, err1, err2)
					return "", nil, true, false
				}
			} else {
				var err error
				dstHost, err = dnsQuery(originHost, first)
				if err != nil {
					logger.Printf("DNS %s fail: %s", originHost, err)
					return "", nil, true, false
				}
				logger.Printf("DNS %s -> %s", originHost, dstHost)
			}
		} else {
			disableRedirect = (*policy.Host)[0] == '^'
			if disableRedirect {
				dstHost = (*policy.Host)[1:]
			} else {
				dstHost = *policy.Host
			}
		}
		if !disableRedirect {
			var ipPolicy *Policy
			dstHost, ipPolicy, err = ipRedirect(logger, dstHost)
			if err != nil {
				logger.Println("IP redirect error:", err)
				return "", nil, true, false
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
	return
}

type BoolWithDefault uint8

const (
	BoolUnset BoolWithDefault = iota
	BoolFalse
	BoolTrue
)

func (b *BoolWithDefault) UnmarshalJSON(data []byte) error {
	s := string(data)
	switch s {
	case "null":
		*b = BoolUnset
	case "false":
		*b = BoolFalse
	case "true":
		*b = BoolTrue
	default:
		return fmt.Errorf("Invalid bool: %s", s)
	}
	return nil
}

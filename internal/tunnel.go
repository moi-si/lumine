package lumine

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"

	log "github.com/moi-si/mylog"
)

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
	} else {
		br := bufio.NewReader(cliConn)
		peekBytes, err := br.Peek(10)
		if err != nil {
			if len(peekBytes) == 0 && errors.Is(err, io.EOF) {
				logger.Error("Empty tunnel")
			} else {
				logger.Error("Read first packet:", err)
			}
			return
		}

		if peekBytes[0] == 0x16 && peekBytes[1] == 0x03 {
			payloadLen := binary.BigEndian.Uint16(peekBytes[3:5])
			if ok := handleTLS(logger, payloadLen, p, replyFirst, originHost, target,
				br, cliConn, dstConn); !ok {
				return
			}
		} else if bytes.HasPrefix(peekBytes, []byte("GET ")) ||
			bytes.HasPrefix(peekBytes, []byte("POST ")) ||
			bytes.HasPrefix(peekBytes, []byte("HEAD ")) ||
			bytes.HasPrefix(peekBytes, []byte("PUT ")) ||
			bytes.HasPrefix(peekBytes, []byte("DELETE ")) ||
			bytes.HasPrefix(peekBytes, []byte("OPTIONS ")) ||
			bytes.HasPrefix(peekBytes, []byte("TRACE ")) ||
			bytes.HasPrefix(peekBytes, []byte("PATCH ")) {
			req, err := http.ReadRequest(br)
			if err == nil {
				if ok := handleHTTP(logger, req,
					replyFirst, originHost, target,
					cliConn, dstConn); !ok {
					return
				}
			} else {
				logger.Error("Trying parsing HTTP: ", err)
			}
		} else {
			logger.Info("Unknown protocol")
		}
	}

	srcConnTCP := cliConn.(*net.TCPConn)
	dstConnTCP := dstConn.(*net.TCPConn)
	done := make(chan struct{})
	go func() {
		if _, err := io.Copy(dstConnTCP, srcConnTCP); err == nil {
			if err = srcConnTCP.CloseRead(); err == nil {
				logger.Debug("src: closed read")
			} else {
				logger.Debug("src: close read: ", err)
			}
		} else if !isUseOfClosedConn(err) {
			logger.Error("Forward", originHost, "->", cliConn.RemoteAddr().String()+":", err)
			closeBoth()
		}
		done <- struct{}{}
	}()
	if _, err := io.Copy(srcConnTCP, dstConnTCP); err == nil {
		if err = dstConnTCP.CloseRead(); err == nil {
			logger.Debug("dest: closed read")
		} else {
			logger.Debug("dest: close read: ", err)
		}
		<-done
	} else if !isUseOfClosedConn(err) {
		logger.Error("Forward", cliConn.RemoteAddr().String(), "->", originHost+":", err)
		closeBoth()
	}
}

func handleHTTP(logger *log.Logger, req *http.Request,
	replyFirst bool, originHost, target string,
	cliConn, dstConn net.Conn) (ok bool) {
	var err error
	defer func() {
		if err := req.Body.Close(); err != nil {
			logger.Debug("Close HTTP body: ", err)
		}
	}()

	host := req.Host
	if host == "" {
		host = req.URL.Host
		if host == "" {
			host = originHost
		}
	}
	logger.Info(req.Method, req.URL, "to", host)

	var p Policy
	if domainPolicy, exists := domainMatcher.Find(host); exists {
		p = mergePolicies(domainPolicy, &defaultPolicy)
	} else {
		p = defaultPolicy
	}
	if p.Host != nil && *p.Host != "" {
		if (*p.Host)[0] != '^' {
			_, ipPolicy, err := ipRedirect(logger, *p.Host)
			if err != nil {
				logger.Error("IP redirect:", err)
				return
			}
			if ipPolicy != nil {
				p = mergePolicies(&p, ipPolicy, &defaultPolicy)
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
	return true
}

func handleTLS(logger *log.Logger, payloadLen uint16,
	p Policy, replyFirst bool, originHost, target string,
	br *bufio.Reader, cliConn, dstConn net.Conn) (ok bool) {
	record := make([]byte, 5+payloadLen)
	if _, err := io.ReadFull(br, record); err != nil {
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
			if domainPolicy, exists := domainMatcher.Find(sniStr); exists {
				sniPolicy = mergePolicies(domainPolicy, &defaultPolicy)
			} else {
				sniPolicy = defaultPolicy
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
			logger.Info("ClientHello sent in fragments")
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
			logger.Info("ClientHello sent with fake packet")
		}
	}
	return true
}

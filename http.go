package main

import (
	"context"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/moi-si/mylog"
)

const (
	status500 = "500 Internal Server Error"
	status403 = "403 Forbidden"
)

var httpConnID uint32

func httpAccept(addr *string, serverAddr string) {
	var listenAddr string
	if *addr == "" {
		listenAddr = serverAddr
	} else {
		listenAddr = *addr
	}
	if listenAddr == "" {
		fmt.Println("HTTP bind address not specified")
		return
	}
	if listenAddr == "none" {
		return
	}

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           http.HandlerFunc(handleHTTP),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if listenAddr[0] == ':' {
		listenAddr = "0.0.0.0" + listenAddr
	}
	logger := log.New(os.Stdout, "[H00000]", log.LstdFlags, logLevel)
	logger.Info("Listening on", "http://"+listenAddr)

	if err := srv.ListenAndServe(); err != nil {
		logger.Error("ListenAndServe:", err)
		return
	}
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	connID := atomic.AddUint32(&httpConnID, 1)
	if connID > 0xFFFFF {
		atomic.StoreUint32(&httpConnID, 0)
		connID = 0
	}
	logger := log.New(os.Stdout, fmt.Sprintf("[H%05x]", connID), log.LstdFlags, logLevel)
	logger.Info(req.RemoteAddr, "- \"", req.Method, req.RequestURI, req.Proto, "\"")

	if req.Method == http.MethodConnect {
		handleConnect(logger, w, req)
		return
	}

	if !req.URL.IsAbs() {
		logger.Error("URI not fully qualified")
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}

	forwardHTTPRequest(logger, w, req)
}

func handleConnect(logger *log.Logger, w http.ResponseWriter, req *http.Request) {
	oldDest := req.Host
	if oldDest == "" {
		logger.Error("Empty host")
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	originHost, dstPort, err := net.SplitHostPort(oldDest)
	if err != nil {
		logger.Error("SplitHostPort:", err)
		return
	}

	dstHost, policy, fail, block := genPolicy(logger, originHost)
	if fail {
		http.Error(w, status500, http.StatusInternalServerError)
		return
	}
	if block {
		logger.Error("Connection blocked")
		http.Error(w, status403, http.StatusForbidden)
		return
	}

	logger.Info("Policy:", policy)

	if policy.Mode == ModeBlock {
		http.Error(w, "", http.StatusForbidden)
		return
	}

	if policy.Port != 0 && policy.Port != -1 {
		dstPort = strconv.FormatInt(int64(policy.Port), 10)
	}

	dest := net.JoinHostPort(dstHost, dstPort)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		logger.Error("Hijacking not supported")
		http.Error(w, status500, http.StatusInternalServerError)
		return
	}
	cliConn, _, err := hijacker.Hijack()
	if err != nil {
		logger.Error("Hijack fail:", err)
		http.Error(w, status500, http.StatusInternalServerError)
		return
	}

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

	replyFirst := policy.ReplyFirst == BoolTrue
	if replyFirst {
		_, err = cliConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		if err != nil {
			logger.Error("Write 200:", err)
			return
		}
	} else {
		dstConn, err = net.Dial("tcp", dest)
		if err != nil {
			logger.Error("Connection failed:", err)
			_, err = cliConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			if err != nil {
				logger.Error("Write 502:", err)
			}
			return
		}
		_, err = cliConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		if err != nil {
			logger.Error("Write 200:", err)
			return
		}
	}

	handleTunnel(policy, replyFirst, dstConn, cliConn,
		logger, dest, originHost, closeBoth)
}

func forwardHTTPRequest(logger *log.Logger, w http.ResponseWriter, originReq *http.Request) {
	host := originReq.Host
	if host == "" {
		host = originReq.URL.Host
	}
	if host == "" {
		logger.Error("Cannot determine target host")
		http.Error(w, "400 Bad Request", http.StatusBadRequest)
		return
	}

	originHost, port, err := net.SplitHostPort(host)
	if err != nil {
		originHost = host
		if originReq.URL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	logger.Info(originReq.Method, originReq.URL, "to", host)

	var p Policy
	if domainPolicy, exists := domainMatcher.Find(originHost); exists {
		p = mergePolicies(domainPolicy, &defaultPolicy)
	} else {
		p = defaultPolicy
	}

	if p.Host != nil && *p.Host != "" {
		if (*p.Host)[0] != '^' {
			_, ipPolicy, err := ipRedirect(logger, *p.Host)
			if err != nil {
				logger.Error("IP redirect:", err)
				http.Error(w, status500, http.StatusInternalServerError)
				return
			}
			if ipPolicy != nil {
				p = mergePolicies(&p, ipPolicy, &defaultPolicy)
			}
		}
	}

	if p.HttpStatus != 0 && p.HttpStatus != -1 {
		if p.HttpStatus == 301 || p.HttpStatus == 302 {
			scheme := originReq.URL.Scheme
			if scheme == "" {
				scheme = "https"
			}
			location := scheme + "://" + host + originReq.URL.RequestURI()
			w.Header().Set("Location", location)
		}
		w.WriteHeader(p.HttpStatus)
		logger.Info("Sent", p.HttpStatus, http.StatusText(p.HttpStatus))
		return
	}

	if p.Mode == ModeBlock {
		logger.Info("Connection blocked")
		http.Error(w, status403, http.StatusForbidden)
		return
	}

	dstHost := originHost
	dstPort := port

	if p.Host != nil && *p.Host != "" {
		if *p.Host == "self" {
			dstHost = originHost
			logger.Info("Host:", dstHost)
		} else if strings.HasPrefix(*p.Host, "^") {
			dstHost = (*p.Host)[1:]
		} else {
			dstHost = *p.Host
			if strings.HasPrefix(dstHost, tagPrefix) {
				if dstHost, err = getFromIPPool(dstHost[1:]); err != nil {
					logger.Error(err)
					http.Error(w, status500, http.StatusInternalServerError)
					return
				}
				logger.Info("Host:", *p.Host, "->", dstHost)
			} else {
				logger.Info("Host:", *p.Host)
			}
		}
	}

	if p.Port != 0 && p.Port != -1 {
		dstPort = strconv.FormatInt(int64(p.Port), 10)
	}

	disableRedirect := p.Host != nil && strings.HasPrefix(*p.Host, "^")
	if !disableRedirect {
		var ipPolicy *Policy
		dstHost, ipPolicy, err = ipRedirect(logger, dstHost)
		if err != nil {
			logger.Error("IP redirect:", err)
			http.Error(w, status500, http.StatusInternalServerError)
			return
		}
		if ipPolicy != nil {
			p = mergePolicies(&p, ipPolicy, &defaultPolicy)
			if p.Mode == ModeBlock {
				http.Error(w, status403, http.StatusForbidden)
				return
			}
		}
	}

	outReq := originReq.Clone(context.Background())
	
	targetAddr := net.JoinHostPort(dstHost, dstPort)
	outReq.URL.Host = targetAddr
	outReq.Host = targetAddr
	
	if outReq.URL.Scheme == "" {
		outReq.URL.Scheme = "http"
	}
	
	outReq.Header.Del("Proxy-Authorization")
	outReq.Header.Del("Proxy-Connection")
	if outReq.Header.Get("Connection") == "" {
		outReq.Header.Set("Connection", "close")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil

	if p.ConnectTimeout > 0 {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: p.ConnectTimeout}
			return d.DialContext(ctx, network, addr)
		}
	}

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		logger.Error("Transport:", err)
		http.Error(w, "502 Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	maps.Copy(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	if _, err = io.Copy(w, resp.Body); err != nil {
		logger.Error("Copy response body:", err)
	}
}
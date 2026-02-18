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
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	outReq := originReq.Clone(context.Background())
	outReq.Host = outReq.URL.Host
	outReq.Header.Del("Proxy-Authorization")
	outReq.Header.Del("Proxy-Connection")
	if outReq.Header.Get("Connection") == "" {
		outReq.Header.Set("Connection", "close")
	}

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		logger.Error("Transport:", err)
	}
	defer resp.Body.Close()

	maps.Copy(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	if _, err = io.Copy(w, resp.Body); err != nil {
		logger.Error("Copying response body:", err)
	}
}

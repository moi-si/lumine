package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const status500 = "500 Internal Server Error"

var httpConnID uint32

func httpAccept(addr *string, serverAddr string, done chan struct{}) {
	defer func() { done <- struct{}{} }()
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
	fmt.Println("Listening on", "http://"+listenAddr)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Println("HTTP ListenAndServe:", err)
		return
	}
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	connID := atomic.AddUint32(&httpConnID, 1)
	if connID > 0xFFFFF {
		atomic.StoreUint32(&httpConnID, 0)
		connID = 0
	}
	logger := log.New(os.Stdout, fmt.Sprintf("[H%05x] ", connID), log.LstdFlags)
	logger.Printf("%s - \"%s %s %s\"", req.RemoteAddr, req.Method, req.RequestURI, req.Proto)

	if req.Method == http.MethodConnect {
		handleConnect(logger, w, req)
		return
	}

	if !req.URL.IsAbs() {
		logger.Println("URI not fully qualified")
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}

	forwardHTTPRequest(logger, w, req)
}

func handleConnect(logger *log.Logger, w http.ResponseWriter, req *http.Request) {
	oldDest := req.Host
	if oldDest == "" {
		logger.Println("Empty host")
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	originHost, dstPort, err := net.SplitHostPort(oldDest)
	if err != nil {
		logger.Println("SplitHostPort fail:", err)
		return
	}

	dstHost, policy, fail := genPolicy(logger, originHost)
	if fail {
		http.Error(w, status500, http.StatusInternalServerError)
		return
	}

	logger.Println("Policy:", policy)

	if policy.Mode == ModeBlock {
		http.Error(w, "", http.StatusForbidden)
		return
	}

	if policy.Port != 0 && policy.Port != -1 {
		dstPort = fmt.Sprintf("%d", policy.Port)
	}

	dest := net.JoinHostPort(dstHost, dstPort)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		logger.Println("Hijacking not supported")
		http.Error(w, status500, http.StatusInternalServerError)
		return
	}
	cliConn, _, err := hijacker.Hijack()
	if err != nil {
		logger.Println("Hijack fail:", err)
		http.Error(w, status500, http.StatusInternalServerError)
		return
	}

	var (
		once    sync.Once
		dstConn net.Conn
	)
	closeBoth := func() {
		once.Do(func() {
			cliConn.Close()
			if dstConn != nil {
				dstConn.Close()
			}
		})
	}
	defer closeBoth()

	replyFirst := policy.ReplyFirst == BoolTrue
	if replyFirst {
		_, err = cliConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		if err != nil {
			logger.Println("Write 200 error:", err)
			return
		}
	} else {
		dstConn, err = net.Dial("tcp", dest)
		if err != nil {
			logger.Println("Connection failed:", err)
			_, err = cliConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			if err != nil {
				logger.Println("Write 502 error:", err)
			}
			return
		}
		_, err = cliConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		if err != nil {
			logger.Println("Write 200 error:", err)
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
		logger.Println("Transport error:", err)
	}
	defer resp.Body.Close()

	maps.Copy(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	if _, err = io.Copy(w, resp.Body); err != nil {
		logger.Println("Error copying response body:", err)
	}
}

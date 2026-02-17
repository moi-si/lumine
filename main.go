package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "moi-si/lumine v0.7.0")
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

	if len(ipPools) != 0 {
		for _, pool := range ipPools {
			defer pool.Close()
		}
	}

	done := make(chan struct{})
	go socks5Accept(addr, socks5Addr, done)
	httpAccept(hAddr, httpAddr)
	<-done
}

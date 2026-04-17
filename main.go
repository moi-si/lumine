package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	lumine "github.com/moi-si/lumine/internal"
)

func main() {
	fmt.Fprintln(os.Stderr, "moi-si/lumine", lumine.Version)
	fmt.Fprintln(os.Stderr, "")
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	configPath := flag.String("c", "config.json", "Config file path")
	addr := flag.String("b", "", "SOCKS5 bind address (default: address from config file)")
	hAddr := flag.String("hb", "", "HTTP bind address (default: address from config file)")
	maxprocs := flag.Int("mp", 0, "GOMAXPROCS")
	flag.Parse()

	socks5Addr, httpAddr, err := lumine.LoadConfig(*configPath)
	if err != nil {
		fmt.Println("Failed to load config:", err)
		return
	}

	if *maxprocs > 0 {
		runtime.GOMAXPROCS(*maxprocs)
	}

	runtime.GC()
	done := make(chan struct{})
	go lumine.SOCKS5Accept(addr, socks5Addr, done)
	lumine.HTTPAccept(hAddr, httpAddr)
	<-done
}

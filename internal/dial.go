package lumine

import (
	"context"
	"errors"
	"net"
	"time"
)

// TCP-only.
var globalDialer net.Dialer

type OutboundLocalAddrOption struct {
	Enabled       bool   `json:"enabled"`
	BindIP        string `json:"bind_ip"`
	BindZone      string `json:"bind_zone"`
	DetectNetwork string `json:"detect_network"`
	DetectTarget  string `json:"detect_target"`
	DialTimeout   string `json:"dial_timeout"`
}

func setOutboundLocalAddr(option OutboundLocalAddrOption) error {
	if !option.Enabled {
		return nil
	}
	var bindIP net.IP
	var bindZone string
	switch option.BindIP {
	case "auto", "":
		network := option.DetectNetwork
		if network == "" {
			network = "udp"
		}
		if network != "tcp" && network != "udp" {
			return errors.New("invalid auto_detect_network: " + network)
		}
		var timeout time.Duration
		if option.DialTimeout == "" {
			timeout = 10 * time.Second
		} else {
			var err error
			timeout, err = time.ParseDuration(option.DialTimeout)
			if err != nil {
				return wrap("invalid auto_detect_timeout: "+option.DialTimeout, err)
			}
		}
		target := option.DetectTarget
		if target == "" {
			target = "8.8.8.8:53"
		}
		conn, err := net.DialTimeout(network, target, timeout)
		if err != nil {
			return wrap("dial error", err)
		}
		defer conn.Close()
		switch laddr := conn.LocalAddr().(type) {
		case *net.TCPAddr:
			bindIP = laddr.IP
			bindZone = laddr.Zone
		case *net.UDPAddr:
			bindIP = laddr.IP
			bindZone = laddr.Zone
		default:
			return errors.New("unsupported network")
		}
	default:
		bindIP = net.ParseIP(option.BindIP)
		if bindIP == nil {
			return errors.New("invalid bind_ip: " + option.BindIP)
		}
		bindZone = option.BindZone
	}
	globalDialer.LocalAddr = &net.TCPAddr{IP: bindIP, Zone: bindZone}
	return nil
}

func dialTimeout(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return globalDialer.DialContext(timeoutCtx, network, addr)
}

func dialTCPTimeout(addr string, timeout time.Duration) (net.Conn, error) {
	return dialTimeout(context.Background(), "tcp", addr, timeout)
}

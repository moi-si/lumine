package lumine

import (
	"context"
	"errors"
	"net"
	"time"
)

type dialer struct {
	ipv4 net.Dialer
	ipv6 net.Dialer
}

func (d *dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if addr[0] == '[' {
		return d.ipv6.DialContext(ctx, network, addr)
	}
	return d.ipv4.DialContext(ctx, network, addr)
}

// TCP-only.
var globalDialer dialer

type OutboundLocalAddrOption struct {
	Enabled       bool   `json:"enabled"`
	BindIPv4      string `json:"bind_ipv4"`
	BindIPv6      string `json:"bind_ipv6"`
	BindZone      string `json:"bind_zone"`
	DetectNetwork string `json:"detect_network"`
	DetectTarget4 string `json:"detect_ipv4_target"`
	DetectTarget6 string `json:"detect_ipv6_target"`
	DialTimeout   string `json:"dial_timeout"`
}

func getBindIP(
	bindIPStr,
	zone,
	detectNetwork,
	detectTarget,
	defalutDetectTarget string,
	dialTimeout time.Duration,
) (bindIP net.IP, bindZone string, err error) {
	switch bindIPStr {
	case "":
	case "auto":
		if detectTarget == "" {
			detectTarget = defalutDetectTarget
		}
		conn, err := net.DialTimeout(detectNetwork, detectTarget, dialTimeout)
		if err != nil {
			return nil, "", wrap("dial error", err)
		}
		defer conn.Close()
		switch laddr := conn.LocalAddr().(type) {
		case *net.TCPAddr:
			bindIP, bindZone = laddr.IP, laddr.Zone
		case *net.UDPAddr:
			bindIP, bindZone = laddr.IP, laddr.Zone
		default:
			return nil, "", errors.New("unsupported detectNetwork")
		}
	default:
		bindIP = net.ParseIP(bindIPStr)
		if bindIP == nil {
			return nil, "", errors.New("invalid bind IP: " + bindIPStr)
		}
		bindZone = zone
	}
	return
}

func setOutboundLocalAddr(option OutboundLocalAddrOption) error {
	if !option.Enabled {
		return nil
	}
	network := option.DetectNetwork
	if network == "" {
		network = "udp"
	}
	if network != "tcp" && network != "udp" {
		return errors.New("invalid detect_network: " + network)
	}
	var timeout time.Duration
	if option.DialTimeout == "" {
		timeout = 10 * time.Second
	} else {
		var err error
		timeout, err = time.ParseDuration(option.DialTimeout)
		if err != nil {
			return wrap("invalid dial_timeout "+option.DialTimeout, err)
		}
	}
	bindIPv4, _, err := getBindIP(
		option.BindIPv4,
		"",
		network,
		option.DetectTarget4,
		"8.8.8.8:53",
		timeout,
	)
	if err != nil {
		return wrap("set outbound local address (IPv4)", err)
	}
	if bindIPv4 != nil {
		globalDialer.ipv4.LocalAddr = &net.TCPAddr{IP: bindIPv4}
	}
	bindIPv6, zone, err := getBindIP(
		option.BindIPv6,
		option.BindZone,
		network,
		option.DetectTarget6,
		"[2001:4860:4860::8888]:53",
		timeout,
	)
	if err != nil {
		return wrap("set outbound local address (IPv6)", err)
	}
	if bindIPv6 != nil {
		globalDialer.ipv6.LocalAddr = &net.TCPAddr{IP: bindIPv6, Zone: zone}
	}
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

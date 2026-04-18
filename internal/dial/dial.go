package dial

import (
	"context"
	"fmt"
	"net"
	"time"
)

// TCP-only.
var (
	ipv4Dialer net.Dialer
	ipv6Dialer net.Dialer
)

func DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if address[0] == '[' {
		return ipv6Dialer.DialContext(ctx, network, address)
	}
	return ipv4Dialer.DialContext(ctx, network, address)
}

func DialTimeout(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return DialContext(timeoutCtx, network, address)
}

func DialTCPTimeout(address string, timeout time.Duration) (net.Conn, error) {
	return DialTimeout(context.Background(), "tcp", address, timeout)
}

func SelectInterface() error {
	interfaces, err := getFilteredInterfaces()
	if err != nil {
		return err
	}
	var iface *networkInterface
	iface, err = selectInterface(interfaces)
	if err == errNoInterface {
		return err
	} else if err != nil {
		fmt.Println("Failed to select interface automatically:", err)
		iface = selectInterfaceManually(interfaces)
	}
	if iface.ipv4 != nil {
		ipv4Dialer.LocalAddr = &net.TCPAddr{IP: iface.ipv4}
	}
	if iface.ipv6 != nil {
		ipv6Dialer.LocalAddr = &net.TCPAddr{IP: iface.ipv6, Zone: iface.name}
	}
	return nil
}

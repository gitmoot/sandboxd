package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
)

const maxModelRelayConnections = 16

func openModelRelay(listenAddress, target, guestCIDR string) (net.Listener, netip.Prefix, error) {
	if listenAddress == "" && target == "" && guestCIDR == "" {
		return nil, netip.Prefix{}, nil
	}
	if listenAddress == "" || target == "" || guestCIDR == "" {
		return nil, netip.Prefix{}, errors.New("model relay requires listen, loopback target, and guest CIDR together")
	}
	guest, err := netip.ParsePrefix(guestCIDR)
	if err != nil || !guest.Addr().Is4() || !guest.Addr().IsPrivate() ||
		guest.Bits() < 24 || guest.Addr() != guest.Masked().Addr() {
		return nil, netip.Prefix{}, errors.New("model relay guest CIDR must be a canonical private IPv4 /24 or narrower")
	}
	listenHost, _, err := net.SplitHostPort(listenAddress)
	if err != nil || net.ParseIP(listenHost).To4() == nil {
		return nil, netip.Prefix{}, errors.New("model relay listen must have an explicit IPv4 address and port")
	}
	targetHost, _, err := net.SplitHostPort(target)
	if err != nil || net.ParseIP(targetHost) == nil || !net.ParseIP(targetHost).IsLoopback() {
		return nil, netip.Prefix{}, errors.New("model relay target must be an explicit loopback IP and port")
	}
	if _, err := net.ResolveTCPAddr("tcp4", target); err != nil {
		return nil, netip.Prefix{}, fmt.Errorf("invalid model relay target: %w", err)
	}
	listener, err := net.Listen("tcp4", listenAddress)
	if err != nil {
		return nil, netip.Prefix{}, fmt.Errorf("listen for model relay: %w", err)
	}
	return listener, guest, nil
}

// serveModelRelay forwards raw TLS bytes to one loopback endpoint. The broker
// verifies a short-lived client certificate and lease; source filtering here
// is defense in depth, not a substitute for guest-to-host firewall rules.
func serveModelRelay(ctx context.Context, listener net.Listener, target string, guest netip.Prefix) error {
	defer listener.Close()
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-stopped:
		}
	}()

	slots := make(chan struct{}, maxModelRelayConnections)
	for {
		inbound, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		peer, ok := inbound.RemoteAddr().(*net.TCPAddr)
		if !ok {
			_ = inbound.Close()
			continue
		}
		address, ok := netip.AddrFromSlice(peer.IP)
		if !ok || !guest.Contains(address.Unmap()) {
			_ = inbound.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				proxyModelConnection(inbound, target)
			}()
		default:
			_ = inbound.Close()
		}
	}
}

func proxyModelConnection(inbound net.Conn, target string) {
	defer inbound.Close()
	outbound, err := net.DialTimeout("tcp4", target, 5*time.Second)
	if err != nil {
		return
	}
	defer outbound.Close()
	deadline := time.Now().Add(10 * time.Minute)
	_ = inbound.SetDeadline(deadline)
	_ = outbound.SetDeadline(deadline)

	copied := make(chan struct{})
	go func() {
		_, _ = io.Copy(outbound, inbound)
		if tcp, ok := outbound.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		close(copied)
	}()
	_, _ = io.Copy(inbound, outbound)
	_ = inbound.Close() // Also unblocks a guest still writing after the broker exits.
	<-copied
}

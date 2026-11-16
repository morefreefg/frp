// Copyright 2026 The frp Authors
// SPDX-License-Identifier: Apache-2.0
//go:build !frps

package kaboo

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

type ssService struct {
	Port        int
	ctx         context.Context
	cancel      context.CancelFunc
	tcp         net.Listener
	udp         net.PacketConn
	cipher      core.Cipher
	mu          sync.Mutex
	udpSessions map[string]*net.UDPConn
	workers     chan struct{}
	closed      bool
}

func startSS(parent context.Context, password string) (*ssService, error) {
	cipher, err := core.PickCipher(SSMethod, nil, password)
	if err != nil {
		return nil, err
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		tcp.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	s := &ssService{Port: tcp.Addr().(*net.TCPAddr).Port, ctx: ctx, cancel: cancel, tcp: tcp, udp: cipher.PacketConn(udp), cipher: cipher, udpSessions: make(map[string]*net.UDPConn), workers: make(chan struct{}, 128)}
	context.AfterFunc(ctx, s.Close)
	go s.acceptTCP()
	go s.readUDP()
	return s, nil
}

func (s *ssService) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	sessions := make([]*net.UDPConn, 0, len(s.udpSessions))
	for _, c := range s.udpSessions {
		sessions = append(sessions, c)
	}
	s.mu.Unlock()
	s.cancel()
	s.tcp.Close()
	s.udp.Close()
	for _, c := range sessions {
		c.Close()
	}
}

func (s *ssService) acceptTCP() {
	for {
		raw, err := s.tcp.Accept()
		if err != nil {
			return
		}
		select {
		case s.workers <- struct{}{}:
		default:
			raw.Close()
			continue
		}
		go func() {
			defer func() { <-s.workers }()
			defer raw.Close()
			stop := context.AfterFunc(s.ctx, func() { raw.Close() })
			defer stop()
			raw.SetDeadline(time.Now().Add(10 * time.Second))
			secured := s.cipher.StreamConn(raw)
			target, err := socks.ReadAddr(secured)
			if err != nil {
				log.Printf("kaboo SS TCP handshake rejected: %v", err)
				return
			}
			dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
			remote, err := dialer.DialContext(s.ctx, "tcp", target.String())
			if err != nil {
				log.Printf("kaboo SS TCP destination connection failed: %v", err)
				return
			}
			defer remote.Close()
			stopRemote := context.AfterFunc(s.ctx, func() { remote.Close() })
			defer stopRemote()
			raw.SetDeadline(time.Time{})
			pipeConnections(&ssHalfConn{Conn: secured, raw: raw}, remote)
		}()
	}
}

type ssHalfConn struct {
	net.Conn
	raw net.Conn
}

func (c *ssHalfConn) CloseWrite() error {
	if h, ok := c.raw.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return nil
}

func pipeConnections(a, b net.Conn) {
	done := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(b, a)
		if h, ok := b.(interface{ CloseWrite() error }); ok {
			_ = h.CloseWrite()
		}
		done <- struct{}{}
	}()
	_, _ = io.Copy(a, b)
	if h, ok := a.(interface{ CloseWrite() error }); ok {
		_ = h.CloseWrite()
	}
	<-done
}

func (s *ssService) readUDP() {
	buf := make([]byte, 65535)
	for {
		n, source, err := s.udp.ReadFrom(buf)
		if err != nil {
			if s.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		target := socks.SplitAddr(buf[:n])
		if target == nil {
			continue
		}
		packet := append([]byte(nil), buf[:n]...)
		select {
		case s.workers <- struct{}{}:
		default:
			continue
		}
		go func() { defer func() { <-s.workers }(); s.forwardUDP(source, target.String(), packet[len(target):]) }()
	}
}

func (s *ssService) forwardUDP(source net.Addr, target string, payload []byte) {
	remote, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return
	}
	id := source.String() + "|" + remote.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	conn := s.udpSessions[id]
	if conn == nil {
		if len(s.udpSessions) >= 512 {
			return
		}
		conn, err = net.DialUDP("udp", nil, remote)
		if err != nil {
			return
		}
		s.udpSessions[id] = conn
		go s.udpResponses(id, conn, source, remote)
	}
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	_, _ = conn.Write(payload)
}

func (s *ssService) udpResponses(id string, conn *net.UDPConn, source net.Addr, target net.Addr) {
	defer func() {
		conn.Close()
		s.mu.Lock()
		if s.udpSessions[id] == conn {
			delete(s.udpSessions, id)
		}
		s.mu.Unlock()
	}()
	header := socks.ParseAddr(target.String())
	if header == nil {
		return
	}
	buf := make([]byte, 65535)
	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := conn.Read(buf[len(header):])
		if err != nil {
			return
		}
		copy(buf, header)
		if _, err = s.udp.WriteTo(buf[:len(header)+n], source); err != nil {
			return
		}
	}
}

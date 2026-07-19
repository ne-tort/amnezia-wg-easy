package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gotd/td/crypto"
	"github.com/gotd/td/mtproxy"
	"github.com/gotd/td/mtproxy/obfuscator"
	"github.com/gotd/td/proto/codec"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/dcs"
)

func parseProxy(raw string) (host, port, addr string, secret []byte, err error) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "tg://proxy?") {
		raw = "https://t.me/proxy?" + strings.TrimPrefix(raw, "tg://proxy?")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", "", nil, err
	}
	q := u.Query()
	host = q.Get("server")
	port = q.Get("port")
	sec := q.Get("secret")
	if host == "" || port == "" || sec == "" {
		return "", "", "", nil, fmt.Errorf("missing server/port/secret")
	}
	secret, err = hex.DecodeString(sec)
	if err != nil {
		return "", "", "", nil, fmt.Errorf("secret hex: %w", err)
	}
	return host, port, net.JoinHostPort(host, port), secret, nil
}

func stepTCP(addr string) error {
	d := net.Dialer{Timeout: 8 * time.Second}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("tcp dial: %w", err)
	}
	_ = c.Close()
	fmt.Println("  [1] TCP OK")
	return nil
}

func stepTLSProbe(host, addr string) {
	d := net.Dialer{Timeout: 8 * time.Second}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		fmt.Printf("  [2] TLS probe dial FAIL: %v\n", err)
		return
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	tc := tls.Client(c, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err := tc.Handshake(); err != nil {
		fmt.Printf("  [2] browser TLS (SNI=%s): FAIL %v\n", host, err)
		return
	}
	st := tc.ConnectionState()
	sub := ""
	if len(st.PeerCertificates) > 0 {
		sub = st.PeerCertificates[0].Subject.String()
	}
	fmt.Printf("  [2] browser TLS OK subject=%s\n", sub)
}

func stepObfuscator(addr string, secret []byte) error {
	s, err := mtproxy.ParseSecret(secret)
	if err != nil {
		return fmt.Errorf("ParseSecret: %w", err)
	}
	fmt.Printf("  [3] ParseSecret type=%d tag=%02x cloak=%q\n", s.Type, s.Tag, s.CloakHost)

	d := net.Dialer{Timeout: 8 * time.Second}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))

	var obs *obfuscator.Conn
	switch s.Type {
	case mtproxy.Simple, mtproxy.Secured:
		obs = obfuscator.Obfuscated2(crypto.DefaultRand(), c)
	case mtproxy.TLS:
		obs = obfuscator.FakeTLS(crypto.DefaultRand(), c)
	default:
		return fmt.Errorf("unknown secret type %d", s.Type)
	}

	tag := codec.PaddedIntermediateClientStart
	if s.Type != mtproxy.TLS {
		if _, ok := s.ExpectedCodec(); ok {
			tag = [4]byte{s.Tag, s.Tag, s.Tag, s.Tag}
		}
	}
	t0 := time.Now()
	if err := obs.Handshake(tag, 2, s); err != nil {
		return fmt.Errorf("obfuscator handshake: %w", err)
	}
	fmt.Printf("  [4] Obfuscator handshake OK in %s\n", time.Since(t0).Round(time.Millisecond))
	return nil
}

func stepTelegram(addr string, secret []byte) error {
	resolver, err := dcs.MTProxy(addr, secret, dcs.MTProxyOptions{})
	if err != nil {
		return fmt.Errorf("MTProxy resolver: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := telegram.NewClient(6, "eb06d4abfb49dc3eeb1aeb98ae0f581e", telegram.Options{
		Resolver:  resolver,
		NoUpdates: true,
	})
	t0 := time.Now()
	return client.Run(ctx, func(ctx context.Context) error {
		cfg, err := client.API().HelpGetNearestDC(ctx)
		if err != nil {
			return fmt.Errorf("HelpGetNearestDC: %w", err)
		}
		fmt.Printf("  [5] Telegram RPC OK in %s nearest_dc=%d this_dc=%d country=%s\n",
			time.Since(t0).Round(time.Millisecond), cfg.NearestDC, cfg.ThisDC, cfg.Country)
		return nil
	})
}

func check(raw string, skipRPC bool) error {
	host, _, addr, secret, err := parseProxy(raw)
	if err != nil {
		return err
	}
	fmt.Printf("\n=== CHECK %s secret_len=%d prefix=%02x ===\n", addr, len(secret), secret[0])

	if err := stepTCP(addr); err != nil {
		return err
	}

	sni := host
	if ps, err := mtproxy.ParseSecret(secret); err == nil && ps.CloakHost != "" {
		sni = ps.CloakHost
	}
	stepTLSProbe(sni, addr)

	if err := stepObfuscator(addr, secret); err != nil {
		return err
	}
	if skipRPC {
		fmt.Println("  [5] skipped (--no-rpc)")
		fmt.Println("  RESULT: OK (handshake)")
		return nil
	}
	if err := stepTelegram(addr, secret); err != nil {
		return err
	}
	fmt.Println("  RESULT: OK")
	return nil
}

func main() {
	args := os.Args[1:]
	skipRPC := false
	var links []string
	for _, a := range args {
		if a == "--no-rpc" {
			skipRPC = true
			continue
		}
		links = append(links, a)
	}
	if len(links) < 1 {
		fmt.Println("usage: mtcheck [--no-rpc] <tg://proxy?...> [more...]")
		fmt.Println("note: needs gotd/td @ master (uTLS FakeTLS); v0.114 ee fails on telemt")
		os.Exit(2)
	}
	fail := false
	for _, a := range links {
		if err := check(a, skipRPC); err != nil {
			fmt.Printf("  RESULT: FAIL %v\n", err)
			fail = true
		}
	}
	if fail {
		os.Exit(1)
	}
}

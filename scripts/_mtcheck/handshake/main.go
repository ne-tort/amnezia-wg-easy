package main

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gotd/td/crypto"
	"github.com/gotd/td/mtproxy"
	"github.com/gotd/td/mtproxy/obfuscator"
	"github.com/gotd/td/proto/codec"
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

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: mtcheck-hs <tg://proxy?...>")
		os.Exit(2)
	}
	fail := false
	for _, raw := range os.Args[1:] {
		if err := check(raw); err != nil {
			fmt.Printf("  RESULT: FAIL %v\n", err)
			fail = true
		}
	}
	if fail {
		os.Exit(1)
	}
}

func check(raw string) error {
	host, _, addr, secret, err := parseProxy(raw)
	if err != nil {
		return err
	}
	fmt.Printf("\n=== HS %s secret_len=%d prefix=%02x ===\n", addr, len(secret), secret[0])

	d := net.Dialer{Timeout: 8 * time.Second}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("tcp: %w", err)
	}
	_ = c.Close()
	fmt.Println("  [1] TCP OK")

	s, err := mtproxy.ParseSecret(secret)
	if err != nil {
		return fmt.Errorf("ParseSecret: %w", err)
	}
	sni := host
	if s.CloakHost != "" {
		sni = s.CloakHost
	}
	fmt.Printf("  [3] ParseSecret type=%d tag=%02x cloak=%q\n", s.Type, s.Tag, s.CloakHost)

	{
		c, err := d.Dial("tcp", addr)
		if err != nil {
			return err
		}
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		tc := tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
		if err := tc.Handshake(); err != nil {
			fmt.Printf("  [2] browser TLS FAIL: %v\n", err)
		} else {
			st := tc.ConnectionState()
			sub := ""
			if len(st.PeerCertificates) > 0 {
				sub = st.PeerCertificates[0].Subject.String()
			}
			fmt.Printf("  [2] browser TLS OK subject=%s\n", sub)
		}
		_ = c.Close()
	}

	c, err = d.Dial("tcp", addr)
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
		return fmt.Errorf("unknown type %d", s.Type)
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

	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, rerr := obs.Read(buf)
	if rerr != nil && rerr != io.EOF {
		fmt.Printf("  [4b] peek n=%d err=%v\n", n, rerr)
	} else {
		fmt.Printf("  [4b] peek n=%d err=%v\n", n, rerr)
	}
	fmt.Println("  RESULT: OK (handshake)")
	return nil
}

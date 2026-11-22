package main

import (
	"strings"
	"testing"
)

func TestCSPAllowsIssuerSubpaths(t *testing.T) {
	p := csp("https://kc.example.com/realms/gjallar")
	if !strings.Contains(p, "connect-src 'self' https://kc.example.com/realms/gjallar/;") {
		t.Fatalf("issuer must be a path prefix (trailing /): %s", p)
	}
	if p := csp(""); !strings.Contains(p, "connect-src 'self';") {
		t.Fatalf("no issuer: %s", p)
	}
}

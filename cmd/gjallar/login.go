package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// login runs the OAuth 2.0 Device Authorization Grant (RFC 8628) against
// Keycloak, so the CLI works over SSH and in WSL without a local browser
// callback. The token is cached in ~/.config/gjallar/token.json (0600).
func login(ctx context.Context, args []string, out io.Writer) (int, error) {
	issuer := envOr("GJALLAR_OIDC_ISSUER", "")
	if len(args) > 0 {
		issuer = args[0]
	}
	if issuer == "" {
		return 2, fmt.Errorf("usage: gjallar login <issuer-url>  (or set GJALLAR_OIDC_ISSUER)")
	}
	client := envOr("GJALLAR_OIDC_CLI_CLIENT_ID", "gjallar-cli")
	var disc struct {
		DeviceEndpoint string `json:"device_authorization_endpoint"`
		TokenEndpoint  string `json:"token_endpoint"`
	}
	if err := getJSON(ctx, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", &disc); err != nil {
		return 1, err
	}
	if disc.DeviceEndpoint == "" {
		return 1, fmt.Errorf("issuer does not support the device flow; enable it on client %q", client)
	}
	var dev struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		VerificationURI         string `json:"verification_uri"`
		Interval                int    `json:"interval"`
		ExpiresIn               int    `json:"expires_in"`
	}
	if err := postForm(ctx, disc.DeviceEndpoint, url.Values{"client_id": {client}, "scope": {"openid profile"}}, &dev); err != nil {
		return 1, err
	}
	link := dev.VerificationURIComplete
	if link == "" {
		link = dev.VerificationURI
	}
	fmt.Fprintf(out, "Open %s\nand confirm code %s\n", link, dev.UserCode)
	interval := time.Duration(max(dev.Interval, 5)) * time.Second
	deadline := time.Now().Add(time.Duration(dev.ExpiresIn) * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return 1, ctx.Err()
		case <-time.After(interval):
		}
		var tok struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			ExpiresIn    int    `json:"expires_in"`
			Error        string `json:"error"`
		}
		err := postForm(ctx, disc.TokenEndpoint, url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {dev.DeviceCode}, "client_id": {client},
		}, &tok)
		switch {
		case tok.AccessToken != "":
			if err := saveToken(tok.AccessToken, time.Now().Add(time.Duration(tok.ExpiresIn)*time.Second)); err != nil {
				return 1, err
			}
			fmt.Fprintln(out, "Logged in. Token cached for this user.")
			return 0, nil
		case tok.Error == "slow_down":
			interval += 5 * time.Second
		case tok.Error == "authorization_pending":
		case err != nil:
			return 1, err
		}
	}
	return 1, fmt.Errorf("login timed out")
}

type cachedToken struct {
	AccessToken string    `json:"access_token"`
	Expires     time.Time `json:"expires"`
}

func tokenPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "gjallar", "token.json")
}

func saveToken(tok string, exp time.Time) error {
	p := tokenPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(cachedToken{tok, exp})
	return os.WriteFile(p, b, 0o600)
}

// loadToken returns the env token, else a non-expired cached one.
func loadToken() string {
	if t := os.Getenv("GJALLAR_TOKEN"); t != "" {
		return t
	}
	b, err := os.ReadFile(tokenPath())
	if err != nil {
		return ""
	}
	var c cachedToken
	if json.Unmarshal(b, &c) != nil || time.Now().After(c.Expires.Add(-30*time.Second)) {
		return ""
	}
	return c.AccessToken
}

func getJSON(ctx context.Context, u string, out any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func postForm(ctx context.Context, u string, v url.Values, out any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_ = json.NewDecoder(resp.Body).Decode(out)
	if resp.StatusCode >= 500 {
		return fmt.Errorf("POST %s: %s", u, resp.Status)
	}
	return nil
}

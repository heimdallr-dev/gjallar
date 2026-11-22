// Package client is a tiny Go client for the Gjallar REST API, shared by the
// CLI and the MCP server.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client calls the Gjallar API.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// New builds a client.
func New(base, token string) *Client {
	return &Client{BaseURL: strings.TrimSuffix(base, "/"), Token: token, HTTP: &http.Client{Timeout: 60 * time.Second}}
}

// WithToken returns a copy that sends a different bearer token.
func (c *Client) WithToken(tok string) *Client {
	cp := *c
	cp.Token = tok
	return &cp
}

// Do sends a request and decodes JSON into out (if non-nil).
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, e.Error)
		}
		return fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	if out == nil {
		return nil
	}
	if raw, ok := out.(*json.RawMessage); ok {
		*raw = data
		return nil
	}
	return json.Unmarshal(data, out)
}

// Get is Do with GET.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.Do(ctx, http.MethodGet, path, nil, out)
}

// Post is Do with POST.
func (c *Client) Post(ctx context.Context, path string, body, out any) error {
	return c.Do(ctx, http.MethodPost, path, body, out)
}

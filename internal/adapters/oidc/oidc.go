// Package oidc verifies Keycloak (or any OIDC provider) access tokens with
// the standard library: discovery, JWKS caching, RS256/ES256 signatures and
// role extraction from Keycloak's realm_access / resource_access claims.
package oidc

import (
	"github.com/heimdallr-dev/gjallar/internal/platform/telemetry"

	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Principal is an authenticated caller.
type Principal struct {
	Subject  string   `json:"sub"`
	Username string   `json:"username"`
	Email    string   `json:"email,omitempty"`
	Roles    []string `json:"roles"`
	Groups   []string `json:"groups,omitempty"`
	Client   string   `json:"client,omitempty"` // azp: gjallar-web, gjallar-cli, gjallar-mcp...
}

// HasRole reports role membership.
func (p Principal) HasRole(r string) bool {
	for _, x := range p.Roles {
		if x == r {
			return true
		}
	}
	return false
}

// Verifier checks bearer tokens against an issuer.
type Verifier struct {
	Issuer   string // e.g. https://keycloak.example.com/realms/gjallar
	ClientID string // used for audience/azp and resource_access roles
	HTTP     *http.Client

	mu      sync.RWMutex
	keys    map[string]crypto.PublicKey
	fetched time.Time
	jwksURL string
}

// NewVerifier builds a verifier; keys are fetched lazily.
func NewVerifier(issuer, clientID string) *Verifier {
	return &Verifier{Issuer: strings.TrimSuffix(issuer, "/"), ClientID: clientID, HTTP: &http.Client{Timeout: 10 * time.Second}}
}

var (
	ErrNoToken = errors.New("missing bearer token")
	ErrInvalid = errors.New("invalid token")
)

// FromRequest extracts and verifies the Authorization bearer token.
func (v *Verifier) FromRequest(r *http.Request) (Principal, error) {
	h := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || tok == "" {
		return Principal{}, ErrNoToken
	}
	return v.Verify(r.Context(), tok)
}

type claims struct {
	Iss         string          `json:"iss"`
	Sub         string          `json:"sub"`
	Aud         json.RawMessage `json:"aud"`
	Azp         string          `json:"azp"`
	Exp         int64           `json:"exp"`
	Nbf         int64           `json:"nbf"`
	Username    string          `json:"preferred_username"`
	Email       string          `json:"email"`
	Groups      []string        `json:"groups"`
	Roles       []string        `json:"roles"` // Entra ID, Authentik, Zitadel-style flat roles
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	ResourceAccess map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`
}

// Verify checks signature, issuer, expiry and audience.
func (v *Verifier) Verify(ctx context.Context, raw string) (Principal, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Principal{}, ErrInvalid
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSeg(parts[0], &hdr); err != nil {
		return Principal{}, ErrInvalid
	}
	key, err := v.key(ctx, hdr.Kid)
	if err != nil {
		return Principal{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Principal{}, ErrInvalid
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch hdr.Alg {
	case "RS256":
		pk, ok := key.(*rsa.PublicKey)
		if !ok || rsa.VerifyPKCS1v15(pk, crypto.SHA256, digest[:], sig) != nil {
			return Principal{}, fmt.Errorf("%w: bad signature", ErrInvalid)
		}
	case "ES256":
		pk, ok := key.(*ecdsa.PublicKey)
		if !ok || len(sig) != 64 || !ecdsa.Verify(pk, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return Principal{}, fmt.Errorf("%w: bad signature", ErrInvalid)
		}
	default:
		return Principal{}, fmt.Errorf("%w: unsupported alg %q", ErrInvalid, hdr.Alg)
	}
	var c claims
	if err := decodeSeg(parts[1], &c); err != nil {
		return Principal{}, ErrInvalid
	}
	now := time.Now().Unix()
	switch {
	case c.Iss != v.Issuer:
		return Principal{}, fmt.Errorf("%w: issuer %q", ErrInvalid, c.Iss)
	case c.Exp == 0 || now > c.Exp+30:
		return Principal{}, fmt.Errorf("%w: expired", ErrInvalid)
	case c.Nbf != 0 && now+30 < c.Nbf:
		return Principal{}, fmt.Errorf("%w: not yet valid", ErrInvalid)
	case v.ClientID != "" && !audienceOK(c, v.ClientID):
		return Principal{}, fmt.Errorf("%w: audience", ErrInvalid)
	}
	p := Principal{Subject: c.Sub, Username: c.Username, Email: c.Email, Groups: c.Groups, Client: c.Azp}
	p.Roles = append(p.Roles, c.RealmAccess.Roles...)
	// Any OIDC provider: flat "roles", and group names (Dex, GitLab, Authentik) count as roles too.
	p.Roles = append(p.Roles, c.Roles...)
	for _, g := range c.Groups {
		p.Roles = append(p.Roles, strings.TrimPrefix(g, "/"))
	}
	if p.Username == "" {
		p.Username = c.Email
	}
	if p.Username == "" {
		p.Username = c.Sub
	}
	if ra, ok := c.ResourceAccess[v.ClientID]; ok {
		p.Roles = append(p.Roles, ra.Roles...)
	}
	return p, nil
}

func audienceOK(c claims, client string) bool {
	if c.Azp == client {
		return true
	}
	var one string
	if json.Unmarshal(c.Aud, &one) == nil {
		return one == client
	}
	var many []string
	if json.Unmarshal(c.Aud, &many) == nil {
		for _, a := range many {
			if a == client {
				return true
			}
		}
	}
	return false
}

func decodeSeg(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func (v *Verifier) key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	v.mu.RLock()
	k, ok := v.keys[kid]
	fresh := time.Since(v.fetched) < time.Hour
	v.mu.RUnlock()
	if ok && fresh {
		return k, nil
	}
	if err := v.refresh(ctx); err != nil {
		if ok {
			return k, nil // keep serving the cached key if the IdP is briefly down
		}
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("%w: unknown key id %q", ErrInvalid, kid)
}

func (v *Verifier) refresh(ctx context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if time.Since(v.fetched) < 10*time.Second {
		return nil // rate-limit refreshes on unknown kids
	}
	if v.jwksURL == "" {
		var disc struct {
			JWKSURI string `json:"jwks_uri"`
		}
		if err := v.getJSON(ctx, v.Issuer+"/.well-known/openid-configuration", &disc); err != nil {
			return fmt.Errorf("oidc discovery: %w", err)
		}
		v.jwksURL = disc.JWKSURI
	}
	var set struct {
		Keys []struct {
			Kty, Kid, Use, N, E, Crv, X, Y string
		} `json:"keys"`
	}
	if err := v.getJSON(ctx, v.jwksURL, &set); err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		switch k.Kty {
		case "RSA":
			n, err1 := base64.RawURLEncoding.DecodeString(k.N)
			e, err2 := base64.RawURLEncoding.DecodeString(k.E)
			if err1 == nil && err2 == nil {
				keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
			}
		case "EC":
			x, err1 := base64.RawURLEncoding.DecodeString(k.X)
			y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
			if err1 == nil && err2 == nil && k.Crv == "P-256" {
				keys[k.Kid] = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
			}
		}
	}
	v.keys, v.fetched = keys, time.Now()
	return nil
}

func (v *Verifier) getJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := v.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// ---- HTTP middleware -----------------------------------------------------

type ctxKey struct{}

// WithPrincipal stores the caller in ctx.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext returns the caller.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(Principal)
	return p, ok
}

// Auth is the access policy for Gjallar's HTTP surfaces.
type Auth struct {
	Verifier   *Verifier // nil = auth disabled (dev only)
	AdminRole  string    // default gjallar-admin
	ViewerRole string    // empty = any authenticated user may read
	// OpenPaths skip authentication (e.g. /api/v1/admission for Kyverno,
	// protected by a NetworkPolicy instead). Exact path match.
	OpenPaths map[string]bool
}

// Middleware authenticates every request except health and metrics.
// Reads need the viewer role; writes need the admin role.
func (a Auth) Middleware(next http.Handler) http.Handler {
	admin := a.AdminRole
	if admin == "" {
		admin = "gjallar-admin"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || r.URL.Path == "/metrics" || a.OpenPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		if a.Verifier == nil {
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), Principal{Subject: "anonymous", Username: "dev", Roles: []string{admin}})))
			return
		}
		p, err := a.Verifier.FromRequest(r)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="gjallar"`)
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		write := r.Method != http.MethodGet && r.Method != http.MethodHead
		if (write && !p.HasRole(admin)) || (!write && a.ViewerRole != "" && !p.HasRole(a.ViewerRole) && !p.HasRole(admin)) {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		telemetry.APIUsage.Inc(p.Client, p.Username, map[bool]string{true: "write", false: "read"}[write])
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

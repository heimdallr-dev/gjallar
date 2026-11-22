package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerifyKeycloakToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/gj/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]string{"jwks_uri": srv.URL + "/certs"})
		case "/certs":
			json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kty": "RSA", "kid": "k1", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}}})
		}
	}))
	defer srv.Close()
	iss := srv.URL + "/realms/gj"
	v := NewVerifier(iss, "gjallar")

	tok := sign(t, key, map[string]any{
		"iss": iss, "sub": "u1", "azp": "gjallar", "exp": time.Now().Add(time.Hour).Unix(),
		"preferred_username": "carl", "realm_access": map[string]any{"roles": []string{"gjallar-admin"}},
	})
	p, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if p.Username != "carl" || !p.HasRole("gjallar-admin") {
		t.Fatalf("principal: %+v", p)
	}

	// Non-Keycloak providers: flat "roles" (Entra, Authentik) or groups only (Dex); no preferred_username.
	for _, c := range []map[string]any{{"roles": []string{"gjallar-admin"}}, {"groups": []string{"/gjallar-admin"}}} {
		c["iss"], c["azp"], c["sub"], c["email"], c["exp"] = iss, "gjallar", "u2", "ana@example.org", time.Now().Add(time.Hour).Unix()
		p, err := v.Verify(context.Background(), sign(t, key, c))
		if err != nil || !p.HasRole("gjallar-admin") || p.Username != "ana@example.org" {
			t.Fatalf("generic OIDC %v: %+v %v", c, p, err)
		}
	}

	expired := sign(t, key, map[string]any{"iss": iss, "azp": "gjallar", "exp": time.Now().Add(-time.Hour).Unix()})
	if _, err := v.Verify(context.Background(), expired); err == nil {
		t.Error("expired token accepted")
	}
	wrongAud := sign(t, key, map[string]any{"iss": iss, "azp": "other", "aud": "other", "exp": time.Now().Add(time.Hour).Unix()})
	if _, err := v.Verify(context.Background(), wrongAud); err == nil {
		t.Error("wrong audience accepted")
	}

	// Middleware: viewer can GET, cannot POST.
	viewer := sign(t, key, map[string]any{"iss": iss, "azp": "gjallar", "exp": time.Now().Add(time.Hour).Unix(),
		"realm_access": map[string]any{"roles": []string{"gjallar-viewer"}}})
	h := Auth{Verifier: v, ViewerRole: "gjallar-viewer"}.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	for _, c := range []struct {
		method, tok string
		want        int
	}{{"GET", viewer, 200}, {"POST", viewer, 403}, {"POST", tok, 200}, {"GET", "", 401}} {
		req := httptest.NewRequest(c.method, "/api/v1/findings", nil)
		if c.tok != "" {
			req.Header.Set("Authorization", "Bearer "+c.tok)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s with token=%v: got %d want %d", c.method, c.tok != "", rec.Code, c.want)
		}
	}
}

func sign(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	head := enc(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	body := enc(claims)
	h := sha256.Sum256([]byte(head + "." + body))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return head + "." + body + "." + base64.RawURLEncoding.EncodeToString(sig)
}

package dtrack

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUpload(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/bom" || r.Header.Get("X-Api-Key") != "k" {
			http.Error(w, "bad", 400)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"token":"t-1"}`))
	}))
	defer srv.Close()
	tok, err := Client{URL: srv.URL, APIKey: "k"}.Upload(context.Background(), "harbor.local/shop/web", "1.0", []byte(`{"bomFormat":"CycloneDX"}`))
	if err != nil || tok != "t-1" {
		t.Fatalf("%v %q", err, tok)
	}
	bom, _ := base64.StdEncoding.DecodeString(got["bom"].(string))
	if got["projectName"] != "harbor.local/shop/web" || got["autoCreate"] != true || string(bom) != `{"bomFormat":"CycloneDX"}` {
		t.Fatalf("payload %+v", got)
	}
	if _, err := (Client{URL: srv.URL, APIKey: "wrong"}).Upload(context.Background(), "p", "v", nil); err == nil {
		t.Fatal("HTTP errors must surface")
	}
}

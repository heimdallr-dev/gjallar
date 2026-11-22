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

func TestUploadRetriesUnknownLicenseIDs(t *testing.T) {
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got map[string]any
		_ = json.NewDecoder(r.Body).Decode(&got)
		bom, _ := base64.StdEncoding.DecodeString(got["bom"].(string))
		bodies = append(bodies, string(bom))
		if len(bodies) == 1 {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"status":400,"detail":"Schema validation failed","errors":[
				"$.components[0].licenses: must have at most 1 items but found 2",
				"$.components[0].licenses[1].license.id: does not have a value in the enumeration [\"0BSD\"]"]}`))
			return
		}
		_, _ = w.Write([]byte(`{"token":"t-2"}`))
	}))
	defer srv.Close()
	in := `{"components":[{"name":"debianutils","licenses":[{"license":{"id":"GPL-2.0-only"}},{"license":{"id":"SMAIL-GPL"}}]}]}`
	tok, err := Client{URL: srv.URL, APIKey: "k"}.Upload(context.Background(), "p", "v", []byte(in))
	if err != nil || tok != "t-2" || len(bodies) != 2 {
		t.Fatalf("%v %q %d", err, tok, len(bodies))
	}
	want := `{"components":[{"licenses":[{"license":{"id":"GPL-2.0-only"}},{"license":{"name":"SMAIL-GPL"}}],"name":"debianutils"}]}`
	if bodies[1] != want {
		t.Fatalf("retry body\n got %s\nwant %s", bodies[1], want)
	}
}

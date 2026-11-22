package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/heimdallr-dev/gjallar/internal/client"
)

func TestMCPToolsFlow(t *testing.T) {
	var gotAuth string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path == "/api/v1/findings" && r.URL.Query().Get("band") == "urgent" {
			w.Write([]byte(`[{"vuln_id":"CVE-2024-1","risk":{"value":91,"band":"urgent"}}]`))
			return
		}
		http.NotFound(w, r)
	}))
	defer api.Close()
	s := &Server{API: client.New(api.URL, ""), Version: "test", RequireAuth: true}

	call := func(body, tok string) (int, map[string]any) {
		req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		return rec.Code, m
	}
	if code, _ := call(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`, ""); code != 401 {
		t.Fatalf("unauthenticated call should be 401, got %d", code)
	}
	_, m := call(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, "tok")
	if m["result"].(map[string]any)["protocolVersion"] != protocolVersion {
		t.Fatalf("initialize: %+v", m)
	}
	if code, _ := call(`{"jsonrpc":"2.0","method":"notifications/initialized"}`, "tok"); code != 202 {
		t.Fatalf("notification should be 202, got %d", code)
	}
	_, m = call(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, "tok")
	if n := len(m["result"].(map[string]any)["tools"].([]any)); n != len(tools) {
		t.Fatalf("tools/list returned %d", n)
	}
	_, m = call(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"top_risks","arguments":{"band":"urgent"}}}`, "tok")
	text := m["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "CVE-2024-1") || gotAuth != "Bearer tok" {
		t.Fatalf("tool call: text=%s auth=%q", text, gotAuth)
	}
	_, m = call(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"image_report","arguments":{"digest":"sha256:x"}}}`, "tok")
	if m["result"].(map[string]any)["isError"] != true {
		t.Fatalf("API error should surface as tool error: %+v", m)
	}
}

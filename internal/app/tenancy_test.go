package app

import "testing"

func TestTenancyScope(t *testing.T) {
	ten := &Tenancy{Groups: map[string][]string{"team-shop": {"shop", "shop-staging"}, "team-pay": {"payments"}}, GlobalRoles: []string{"gjallar-admin"}}
	if s := ten.ScopeFor([]string{"gjallar-admin"}, nil); !s.All {
		t.Error("admin must see everything")
	}
	s := ten.ScopeFor([]string{"gjallar-viewer"}, []string{"/team-shop"}) // Keycloak full-path group names work too
	if s.All || !s.Namespace("shop") || !s.Namespace("shop-staging") || s.Namespace("payments") {
		t.Errorf("team-shop scope: %+v", s)
	}
	if !s.AnyWorkload([]string{"payments/api", "shop/web"}) || s.AnyWorkload([]string{"payments/api"}) || s.AnyWorkload(nil) {
		t.Error("AnyWorkload")
	}
	if s := ten.ScopeFor([]string{"gjallar-viewer"}, []string{"unmapped"}); s.All || len(s.NS) != 0 {
		t.Error("unmapped group must see nothing")
	}
	var none *Tenancy
	if !none.ScopeFor(nil, nil).All {
		t.Error("no tenancy configured = everything")
	}
}

package app

import "strings"

// Tenancy maps identity-provider groups (Keycloak "groups" claim) to the
// namespaces their members may see. Holders of a global role see everything.
type Tenancy struct {
	Groups      map[string][]string // "team-shop" → ["shop", "shop-staging"]
	GlobalRoles []string            // e.g. gjallar-admin, gjallar-auditor
}

// Scope is what one caller may see.
type Scope struct {
	All bool
	NS  map[string]bool
}

// Everything is the scope without tenancy.
var Everything = Scope{All: true}

// ScopeFor resolves a caller's scope from their roles and groups.
// A caller in no mapped group sees nothing (not everything).
func (t *Tenancy) ScopeFor(roles, groups []string) Scope {
	if t == nil || len(t.Groups) == 0 {
		return Everything
	}
	for _, r := range roles {
		for _, g := range t.GlobalRoles {
			if r == g {
				return Everything
			}
		}
	}
	s := Scope{NS: map[string]bool{}}
	for _, g := range groups {
		for _, ns := range t.Groups[strings.TrimPrefix(g, "/")] {
			s.NS[ns] = true
		}
	}
	return s
}

// Namespace reports whether ns is visible.
func (s Scope) Namespace(ns string) bool { return s.All || s.NS[ns] }

// AnyWorkload reports whether any "namespace/name" workload is visible.
func (s Scope) AnyWorkload(workloads []string) bool {
	if s.All {
		return true
	}
	for _, w := range workloads {
		if ns, _, _ := strings.Cut(w, "/"); s.NS[ns] {
			return true
		}
	}
	return false
}

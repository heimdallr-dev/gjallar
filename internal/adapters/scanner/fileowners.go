package scanner

import (
	"encoding/json"
	"fmt"
	"strings"
)

// FileOwners indexes a Syft JSON SBOM by file path, so runtime file opens
// (Inspektor Gadget trace_open) can be turned into package names.
// The returned lookup gives the owning package name, or "" if none.
func FileOwners(raw []byte) (func(path string) string, error) {
	var doc struct {
		Artifacts []struct {
			Name      string `json:"name"`
			Type      string `json:"type"`
			Locations []struct {
				Path string `json:"path"`
			} `json:"locations"`
			Metadata struct {
				Files []struct {
					Path string `json:"path"`
				} `json:"files"`
			} `json:"metadata"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse syft json: %w", err)
	}
	owners := map[string]string{}
	add := func(p, name string) {
		if !strings.HasPrefix(p, "/") {
			return // python RECORD paths etc. are relative to site-packages
		}
		p = canonPath(p)
		if _, ok := owners[p]; !ok {
			owners[p] = name
		}
		// libfoo.so.1.2.3 is opened through its SONAME symlinks (libfoo.so.1),
		// which package file lists usually omit.
		for {
			i := strings.LastIndex(p, ".")
			if i < 0 || !onlyDigits(p[i+1:]) || !(strings.HasSuffix(p[:i], ".so") || strings.Contains(p[:i], ".so.")) {
				break
			}
			p = p[:i]
			if _, ok := owners[p]; !ok {
				owners[p] = name
			}
		}
	}
	for _, a := range doc.Artifacts {
		for _, f := range a.Metadata.Files {
			add(f.Path, a.Name)
		}
		// For language packages the location is the artifact itself (a .jar,
		// a Go binary). For OS packages it is the package DB, which many
		// tools read without loading the package, so skip those.
		if !osPackageType(a.Type) {
			for _, l := range a.Locations {
				add(l.Path, a.Name)
			}
		}
	}
	return func(path string) string { return owners[canonPath(path)] }, nil
}

func onlyDigits(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}

// canonPath folds merged-/usr aliases (/lib → /usr/lib, /bin → /usr/bin) so
// a package listing /lib/x/libc.so.6 matches an open of /usr/lib/x/libc.so.6.
func canonPath(p string) string {
	for _, d := range []string{"/lib/", "/lib64/", "/bin/", "/sbin/"} {
		if strings.HasPrefix(p, d) {
			return "/usr" + p
		}
	}
	return p
}

func osPackageType(t string) bool {
	switch t {
	case "deb", "rpm", "apk", "alpm":
		return true
	}
	return false
}

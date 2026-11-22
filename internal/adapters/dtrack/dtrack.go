// Package dtrack exports SBOMs to OWASP Dependency-Track (opt-in), so teams
// that already use it keep their workflow: Gjallar never holds data hostage.
package dtrack

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Client uploads CycloneDX BOMs with `PUT /api/v1/bom` (auto-creating projects).
type Client struct {
	URL    string // https://dtrack.example.com (API server)
	APIKey string // team key with BOM_UPLOAD and PROJECT_CREATION_UPLOAD
	HTTP   *http.Client
}

// Upload sends one BOM for project name@version and returns DT's processing token.
// Dependency-Track validates license IDs against the SPDX list it was built
// with; when Syft knows a newer ID, DT rejects the whole BOM. Upload then
// retries once with only those IDs moved to license.name (text kept).
func (c Client) Upload(ctx context.Context, project, version string, cdx []byte) (string, error) {
	tok, err := c.upload(ctx, project, version, cdx)
	var ve *validationError
	if !errors.As(err, &ve) {
		return tok, err
	}
	fixed, n := unknownLicensesToNames(cdx, ve.errors)
	if n == 0 {
		return "", err
	}
	return c.upload(ctx, project, version, fixed)
}

type validationError struct {
	msg    string
	errors []string
}

func (e *validationError) Error() string { return e.msg }

func (c Client) upload(ctx context.Context, project, version string, cdx []byte) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"projectName": project, "projectVersion": version, "autoCreate": true,
		"bom": base64.StdEncoding.EncodeToString(cdx),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, strings.TrimSuffix(c.URL, "/")+"/api/v1/bom", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", c.APIKey)
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		msg := fmt.Sprintf("dependency-track upload %s@%s: %s %s", project, version, resp.Status, strings.TrimSpace(string(raw[:min(len(raw), 200)])))
		var v struct{ Errors []string }
		if resp.StatusCode == http.StatusBadRequest && json.Unmarshal(raw, &v) == nil && len(v.Errors) > 0 {
			return "", &validationError{msg: msg, errors: v.Errors}
		}
		return "", errors.New(msg)
	}
	var tok struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(raw, &tok)
	return tok.Token, nil
}

var unknownLicenseID = regexp.MustCompile(`^\$((?:\.\w+|\[\d+\])+)\.license\.id: does not have a value in the enumeration`)
var pathPart = regexp.MustCompile(`\.(\w+)|\[(\d+)\]`)

// unknownLicensesToNames rewrites {"license":{"id":X}} to {"license":{"name":X}}
// at each path DT reported as an unknown SPDX ID. It returns the new BOM and
// how many entries changed (0: nothing it could fix, send the error on).
func unknownLicensesToNames(cdx []byte, errs []string) ([]byte, int) {
	var doc any
	dec := json.NewDecoder(bytes.NewReader(cdx))
	dec.UseNumber() // keep numbers exactly as Syft wrote them
	if dec.Decode(&doc) != nil {
		return cdx, 0
	}
	n := 0
	for _, e := range errs {
		m := unknownLicenseID.FindStringSubmatch(e)
		if m == nil {
			continue
		}
		node := doc
		for _, p := range pathPart.FindAllStringSubmatch(m[1], -1) {
			switch cur := node.(type) {
			case map[string]any:
				node = cur[p[1]]
			case []any:
				i, _ := strconv.Atoi(p[2])
				if p[2] == "" || i >= len(cur) {
					node = nil
				} else {
					node = cur[i]
				}
			default:
				node = nil
			}
		}
		entry, _ := node.(map[string]any)
		lic, _ := entry["license"].(map[string]any)
		if id, ok := lic["id"].(string); ok {
			delete(lic, "id")
			lic["name"] = id
			n++
		}
	}
	if n == 0 {
		return cdx, 0
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return cdx, 0
	}
	return out, n
}

// gjallar is the command-line client.
//
// Local mode (no hub; needs syft and grype on PATH) — ideal for CI:
//
//	gjallar scan nginx:1.27 --fail-on high
//
// Hub mode (talks to the Gjallar API; set GJALLAR_URL and GJALLAR_TOKEN):
//
//	gjallar summary | findings | images | posture | licenses | patches
//	gjallar submit <image>      queue a scan on the hub
//	gjallar rematch             re-match all stored SBOMs
//	gjallar patch <digest>      queue a Copa patch
//	gjallar accept <id> <why>   accept a risk (VEX exception)
//	gjallar report <name>       curated analytics report
//	gjallar query "<sql>"       read-only DuckDB SQL over the lakehouse
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/heimdallr-dev/gjallar/internal/adapters/scanner"
	"github.com/heimdallr-dev/gjallar/internal/app"
	"github.com/heimdallr-dev/gjallar/internal/client"
	"github.com/heimdallr-dev/gjallar/internal/domain"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	code, err := dispatch(ctx, cmd, args, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gjallar:", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

func usage(w io.Writer) {
	fmt.Fprint(w, `gjallar — Kubernetes risk, ranked.

Local:  gjallar scan <image> [--json] [--fail-on urgent|high|medium|low] [--source registry|docker|podman|containerd]
Hub:    gjallar summary | findings [--band b --namespace ns --package p] | images | posture | licenses | patches
        gjallar submit <image> | rematch | patch <digest> | accept <finding-id> <reason>
        gjallar report <name> | query "<sql>"
Ops:    gjallar ops refresh-db   (in-cluster CronJob: refresh Grype DB mirror, then re-match)
Auth:   gjallar login <keycloak-realm-url>   (device flow; caches the token)
Env:    GJALLAR_URL (default http://localhost:8080), GJALLAR_TOKEN (overrides the cached token)
`)
}

func hub() *client.Client {
	base := os.Getenv("GJALLAR_URL")
	if base == "" {
		base = "http://localhost:8080"
	}
	return client.New(base, loadToken())
}

func dispatch(ctx context.Context, cmd string, args []string, out io.Writer) (int, error) {
	switch cmd {
	case "version", "--version":
		fmt.Fprintln(out, "gjallar", version)
		return 0, nil
	case "help", "-h", "--help":
		usage(out)
		return 0, nil
	case "scan":
		return scan(ctx, args, out)
	case "ops":
		return ops(ctx, args, out)
	case "login":
		return login(ctx, args, out)
	case "summary":
		return 0, printJSONFrom(ctx, out, "/api/v1/summary")
	case "findings":
		fs := flag.NewFlagSet("findings", flag.ContinueOnError)
		band := fs.String("band", "", "risk band")
		ns := fs.String("namespace", "", "namespace")
		pkg := fs.String("package", "", "package substring")
		limit := fs.Int("limit", 50, "max rows")
		asJSON := fs.Bool("json", false, "JSON output")
		if err := fs.Parse(args); err != nil {
			return 2, err
		}
		q := fmt.Sprintf("/api/v1/findings?limit=%d&band=%s&namespace=%s&package=%s", *limit, *band, *ns, *pkg)
		var rows []app.FindingView
		if err := hub().Get(ctx, q, &rows); err != nil {
			return 1, err
		}
		if *asJSON {
			return 0, json.NewEncoder(out).Encode(rows)
		}
		tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "RISK\tBAND\tVULN\tPACKAGE\tFIX\tWHERE")
		for _, f := range rows {
			fmt.Fprintf(tw, "%d\t%s\t%s%s\t%s %s\t%s\t%s\n", f.Risk.Value, f.Risk.Band, f.VulnID, kev(f.KEV), f.Package, f.Version, dash(f.FixedIn), strings.Join(f.Workloads, ","))
		}
		return 0, tw.Flush()
	case "images":
		return 0, printJSONFrom(ctx, out, "/api/v1/images")
	case "posture":
		return 0, printJSONFrom(ctx, out, "/api/v1/posture")
	case "licenses":
		return 0, printJSONFrom(ctx, out, "/api/v1/licenses?verdict=denied")
	case "patches":
		return 0, printJSONFrom(ctx, out, "/api/v1/patches")
	case "submit":
		if len(args) != 1 {
			return 2, fmt.Errorf("usage: gjallar submit <image>")
		}
		return 0, post(ctx, out, "/api/v1/scan", map[string]string{"image": args[0]})
	case "rematch":
		return 0, post(ctx, out, "/api/v1/rematch", map[string]string{})
	case "patch":
		if len(args) != 1 {
			return 2, fmt.Errorf("usage: gjallar patch <digest>")
		}
		return 0, post(ctx, out, "/api/v1/images/"+args[0]+"/patch", map[string]string{})
	case "accept":
		if len(args) < 2 {
			return 2, fmt.Errorf("usage: gjallar accept <finding-id> <reason...>")
		}
		return 0, post(ctx, out, "/api/v1/findings/"+args[0]+"/accept", map[string]string{"reason": strings.Join(args[1:], " ")})
	case "report":
		if len(args) != 1 {
			return 2, fmt.Errorf("usage: gjallar report <risk_trend|time_to_fix|top_packages|kev_exposure|license_denials|posture_by_check>")
		}
		return 0, printJSONFrom(ctx, out, "/api/v1/analytics/reports/"+args[0])
	case "query":
		if len(args) != 1 {
			return 2, fmt.Errorf(`usage: gjallar query "SELECT ..."`)
		}
		return 0, post(ctx, out, "/api/v1/analytics/query", map[string]string{"sql": args[0]})
	default:
		usage(os.Stderr)
		return 2, fmt.Errorf("unknown command %q", cmd)
	}
}

func scan(ctx context.Context, args []string, out io.Writer) (int, error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "JSON output")
	failOn := fs.String("fail-on", "", "exit 3 if any finding is in this band or above")
	source := fs.String("source", "", "image source: registry, docker, podman, containerd (default: auto)")
	scope := fs.String("scope", "", "squashed (default) or all-layers")
	limit := fs.Int("limit", 30, "rows to print")
	// Accept the image before or after the flags.
	var image string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		image, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if image == "" {
		image = fs.Arg(0)
	}
	if image == "" {
		return 2, fmt.Errorf("usage: gjallar scan <image> [flags]")
	}
	ref, err := domain.ParseImageRef(image)
	if err != nil {
		return 2, err
	}
	rep, err := app.LocalScan(ctx, scanner.Syft{Source: *source, Scope: *scope}, scanner.Grype{}, scanner.BuiltinLicenses{}, domain.DefaultLicensePolicy(), ref)
	if err != nil {
		return 1, err
	}
	if *asJSON {
		if err := json.NewEncoder(out).Encode(rep); err != nil {
			return 1, err
		}
	} else {
		bands := map[domain.RiskBand]int{}
		for _, f := range rep.Findings {
			bands[f.Risk.Band]++
		}
		fmt.Fprintf(out, "%s  %s  %d packages  db %s\n", ref, rep.Distro, rep.Packages, dash(rep.DBVersion))
		fmt.Fprintf(out, "urgent %d · high %d · medium %d · low %d\n\n", bands[domain.BandUrgent], bands[domain.BandHigh], bands[domain.BandMedium], bands[domain.BandLow])
		tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "RISK\tBAND\tVULN\tPACKAGE\tFIX\tWHY")
		for i, f := range rep.Findings {
			if i >= *limit {
				fmt.Fprintf(tw, "…\t\t%d more\t\t\t\n", len(rep.Findings)-i)
				break
			}
			fmt.Fprintf(tw, "%d\t%s\t%s%s\t%s %s\t%s\t%s\n", f.Risk.Value, f.Risk.Band, f.VulnID, kev(f.KEV), f.Package, f.Version, dash(f.FixedIn), strings.Join(f.Risk.Reasons, "; "))
		}
		_ = tw.Flush()
		denied := 0
		for _, l := range rep.Licenses {
			if l.Verdict == domain.LicenseDenied {
				denied++
			}
		}
		if denied > 0 {
			fmt.Fprintf(out, "\n%d package licenses denied by policy (run with --json for details)\n", denied)
		}
	}
	if *failOn != "" {
		threshold := domain.BandRank(domain.RiskBand(*failOn))
		if threshold == 0 {
			return 2, fmt.Errorf("--fail-on must be urgent, high, medium or low")
		}
		for _, f := range rep.Findings {
			if domain.BandRank(f.Risk.Band) >= threshold {
				return 3, fmt.Errorf("findings at or above %q", *failOn)
			}
		}
	}
	return 0, nil
}

func printJSONFrom(ctx context.Context, out io.Writer, path string) error {
	var raw json.RawMessage
	if err := hub().Get(ctx, path, &raw); err != nil {
		return err
	}
	return prettyJSON(out, raw)
}

func post(ctx context.Context, out io.Writer, path string, body any) error {
	var raw json.RawMessage
	if err := hub().Post(ctx, path, body, &raw); err != nil {
		return err
	}
	return prettyJSON(out, raw)
}

func prettyJSON(out io.Writer, raw []byte) error {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		_, err = out.Write(raw)
		return err
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func kev(b bool) string {
	if b {
		return " [KEV]"
	}
	return ""
}

func dash(s string) string {
	if s == "" {
		return "–"
	}
	return s
}

package domain

import (
	"fmt"
	"math"
)

// RiskBand is the bucket a human acts on.
type RiskBand string

const (
	BandUrgent RiskBand = "urgent"
	BandHigh   RiskBand = "high"
	BandMedium RiskBand = "medium"
	BandLow    RiskBand = "low"
)

// BandRank orders bands for sorting and --fail-on thresholds.
func BandRank(b RiskBand) int {
	switch b {
	case BandUrgent:
		return 4
	case BandHigh:
		return 3
	case BandMedium:
		return 2
	case BandLow:
		return 1
	}
	return 0
}

// Reasons that analytics reads back as score inputs.
const (
	ReasonLoaded      = "package loaded at runtime"
	ReasonNeverLoaded = "package never loaded at runtime"
	ReasonExposed     = "workload exposed outside the cluster"
	ReasonFix         = "fix available"
)

// Tri is a three-valued boolean: runtime data may simply be absent.
type Tri int

const (
	TriUnknown Tri = iota
	TriYes
	TriNo
)

// RiskInput is everything the scoring formula looks at.
type RiskInput struct {
	CVSS          float64 // 0..10 base score
	Severity      Severity
	EPSS          float64 // 0..1 probability of exploitation in 30 days
	KEV           bool    // listed in CISA Known Exploited Vulnerabilities
	RuntimeLoaded Tri     // package observed loaded at runtime
	Exposed       bool    // reachable through an Ingress / LB / NodePort
	FixAvailable  bool
	Source        string // secondary matcher that alone reported it, e.g. "osv"
}

// RiskScore is the explainable result: a value, a band and the reasons.
type RiskScore struct {
	Value      int      `json:"value"`
	Band       RiskBand `json:"band"`
	Actionable bool     `json:"actionable"`
	Reasons    []string `json:"reasons"`
}

// Score turns raw vulnerability facts into a 0..100 priority.
//
//	impact     = CVSS / 10            (severity fallback when CVSS is missing)
//	likelihood = 1.0 if KEV, else 0.2 + 0.8 × EPSS
//	context    = runtime (loaded 1.0, unknown 0.8, not loaded 0.3)
//	             × 1.25 when exposed outside the cluster
//	score      = 100 × impact × likelihood × context, capped at 100
//
// The point is ordering, not precision: a reachable, exploited, exposed
// medium outranks an unreachable critical nobody exploits.
func Score(in RiskInput) RiskScore {
	var reasons []string
	cvss := in.CVSS
	if cvss <= 0 {
		cvss = in.Severity.FallbackCVSS()
		reasons = append(reasons, fmt.Sprintf("no CVSS, using %s severity", in.Severity))
	}
	impact := clamp(cvss/10, 0, 1)

	likelihood := 0.2 + 0.8*clamp(in.EPSS, 0, 1)
	if in.KEV {
		likelihood = 1
		reasons = append(reasons, "known exploited (CISA KEV)")
	} else if in.EPSS >= 0.1 {
		reasons = append(reasons, fmt.Sprintf("EPSS %.0f%%", in.EPSS*100))
	}

	context := 0.8
	switch in.RuntimeLoaded {
	case TriYes:
		context = 1.0
		reasons = append(reasons, ReasonLoaded)
	case TriNo:
		context = 0.3
		reasons = append(reasons, ReasonNeverLoaded)
	}
	if in.Exposed {
		context *= 1.25
		reasons = append(reasons, ReasonExposed)
	}

	value := int(math.Round(clamp(100*impact*likelihood*context, 0, 100)))
	if in.FixAvailable {
		reasons = append(reasons, ReasonFix)
	}
	if in.Source != "" {
		reasons = append(reasons, "reported by "+in.Source+" only (no EPSS/KEV data from it)")
	}
	return RiskScore{Value: value, Band: band(value), Actionable: in.FixAvailable, Reasons: reasons}
}

func band(v int) RiskBand {
	switch {
	case v >= 70:
		return BandUrgent
	case v >= 40:
		return BandHigh
	case v >= 15:
		return BandMedium
	default:
		return BandLow
	}
}

func clamp(v, lo, hi float64) float64 {
	return math.Max(lo, math.Min(hi, v))
}

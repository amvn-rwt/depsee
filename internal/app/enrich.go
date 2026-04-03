package app

import (
	"context"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/sync/errgroup"
)

const maxGraphCVEs = 48

// EnrichGraphProgress is called after each PURL vulnerability lookup finishes (done in 1..total).
type EnrichGraphProgress func(done, total int)

// EnrichGraphFromSBOMVulnerabilities fills node CVE fields from CycloneDX vulnerabilities[] only (no network).
func EnrichGraphFromSBOMVulnerabilities(sbom *SBOM, g *Graph) {
	if g == nil || sbom == nil {
		return
	}
	refCVEs := refToCVEEntriesFromSBOM(sbom)
	applyRefCVEsAndAnalyze(sbom, g, refCVEs)
}

// EnrichGraph merges NVD results into ref-scoped CVE rows (starting from SBOM vulnerabilities), then runs blast radius and risk analysis.
// If onProgress is non-nil, it is invoked as each PURL query completes (thread-safe).
func EnrichGraph(ctx context.Context, sbom *SBOM, g *Graph, nvd *NVDClient, onProgress EnrichGraphProgress) error {
	if g == nil || nvd == nil {
		return nil
	}
	refCVEs := refToCVEEntriesFromSBOM(sbom)
	if err := mergeNVDCVEsIntoRefMap(ctx, sbom, g, nvd, refCVEs, onProgress); err != nil {
		return err
	}
	applyRefCVEsAndAnalyze(sbom, g, refCVEs)
	return nil
}

// mergeNVDCVEsIntoRefMap fetches NVD CVE lists per distinct PURL and appends them onto refCVEs[nodeID] with deduplication by CVE id.
func mergeNVDCVEsIntoRefMap(ctx context.Context, sbom *SBOM, g *Graph, nvd *NVDClient, refCVEs map[string][]CVEEntry, onProgress EnrichGraphProgress) error {
	if refCVEs == nil {
		return nil
	}
	refToComp := indexComponents(sbom)

	uniq := make(map[string]struct{})
	for _, n := range g.Nodes {
		c, ok := refToComp[n.ID]
		if !ok {
			continue
		}
		if p := strings.TrimSpace(c.PURL); p != "" {
			uniq[p] = struct{}{}
		}
	}

	purls := make([]string, 0, len(uniq))
	for p := range uniq {
		purls = append(purls, p)
	}
	sort.Strings(purls)

	purlCVEs := make(map[string][]CVEEntry)
	purlErr := make(map[string]bool)
	var mu sync.Mutex
	totalPurls := len(purls)
	var purlDone atomic.Int32

	eg, ctx := errgroup.WithContext(ctx)
	eg.SetLimit(32)
	for _, p := range purls {
		p := p
		eg.Go(func() error {
			cves, err := nvd.CVEsForPURL(ctx, p)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				purlErr[p] = true
			} else {
				purlCVEs[p] = cves
			}
			if onProgress != nil && totalPurls > 0 {
				d := int(purlDone.Add(1))
				onProgress(d, totalPurls)
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return err
	}

	for _, n := range g.Nodes {
		c, ok := refToComp[n.ID]
		if !ok {
			continue
		}
		p := strings.TrimSpace(c.PURL)
		if p == "" {
			continue
		}
		if purlErr[p] {
			continue
		}
		refCVEs[n.ID] = appendCVEsDedupe(refCVEs[n.ID], purlCVEs[p])
	}

	for i := range g.Nodes {
		c, ok := refToComp[g.Nodes[i].ID]
		if !ok {
			continue
		}
		p := strings.TrimSpace(c.PURL)
		if p == "" {
			continue
		}
		if purlErr[p] {
			g.Nodes[i].VulnQueryError = true
		}
	}
	return nil
}

// applyRefCVEsAndAnalyze attaches refCVEs to graph nodes and computes dependents, blast radius, transitive exposure, and risk score.
func applyRefCVEsAndAnalyze(sbom *SBOM, g *Graph, refCVEs map[string][]CVEEntry) {
	if g == nil {
		return
	}
	if refCVEs == nil {
		refCVEs = make(map[string][]CVEEntry)
	}
	refToComp := indexComponents(sbom)

	directCVE := make(map[string]bool, len(g.Nodes))
	for i := range g.Nodes {
		n := &g.Nodes[i]
		c, ok := refToComp[n.ID]
		if !ok {
			n.Severity = "UNKNOWN"
			continue
		}
		n.VulnQueried = true
		cves := cvesForComponent(refCVEs, c)
		n.CVECount = len(cves)
		if len(cves) > 0 {
			directCVE[n.ID] = true
		}
		fillNodeCVEs(n, cves)
	}

	rev := reverseDependents(g.Links)
	fwd := forwardDeps(g.Links)

	for i := range g.Nodes {
		id := g.Nodes[i].ID
		g.Nodes[i].DependentCount = len(rev[id])
		g.Nodes[i].BlastRadius = blastRadius(id, rev)
		if g.Nodes[i].MaxCvss > 0 {
			g.Nodes[i].RiskScore = g.Nodes[i].MaxCvss * (1.0 + float64(g.Nodes[i].BlastRadius))
		}
	}

	memo := make(map[string]bool)
	visiting := make(map[string]bool)
	for i := range g.Nodes {
		id := g.Nodes[i].ID
		if directCVE[id] || !g.Nodes[i].VulnQueried {
			continue
		}
		for _, c := range fwd[id] {
			if subtreeContainsCVE(c, fwd, directCVE, memo, visiting) {
				g.Nodes[i].TransitiveExposure = true
				if g.Nodes[i].Severity == "NONE" {
					g.Nodes[i].Severity = "EXPOSED"
				}
				break
			}
		}
	}
}

// appendCVEsDedupe appends entries from add whose IDs are not already present in existing.
func appendCVEsDedupe(existing []CVEEntry, add []CVEEntry) []CVEEntry {
	seen := make(map[string]struct{}, len(existing)+len(add))
	for _, e := range existing {
		if id := strings.TrimSpace(e.ID); id != "" {
			seen[id] = struct{}{}
		}
	}
	out := append([]CVEEntry(nil), existing...)
	for _, e := range add {
		id := strings.TrimSpace(e.ID)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, e)
	}
	return out
}

func fillNodeCVEs(n *GraphNode, cves []CVEEntry) {
	var max float64
	var maxSev string
	counts := make(map[string]int)
	for _, c := range cves {
		if c.BaseScore > max {
			max = c.BaseScore
			maxSev = strings.TrimSpace(c.BaseSeverity)
		}
		s := strings.ToUpper(strings.TrimSpace(c.BaseSeverity))
		if s == "MODERATE" {
			s = "MEDIUM"
		}
		if s == "" {
			s = severityFromScore(c.BaseScore)
		}
		switch s {
		case "CRITICAL", "HIGH", "MEDIUM", "LOW":
			counts[s]++
		}
	}
	if len(counts) > 0 {
		n.CveSeverityCounts = counts
	}
	n.MaxCvss = max
	n.Severity = aggregateSeverity(cves, max, maxSev)

	list := cves
	if len(list) > maxGraphCVEs {
		list = list[:maxGraphCVEs]
	}
	n.CVEs = make([]GraphCVE, 0, len(list))
	for _, c := range list {
		n.CVEs = append(n.CVEs, GraphCVE{
			ID:           c.ID,
			BaseScore:    c.BaseScore,
			BaseSeverity: strings.TrimSpace(c.BaseSeverity),
		})
	}
}

func aggregateSeverity(cves []CVEEntry, maxScore float64, maxSev string) string {
	if len(cves) == 0 {
		return "NONE"
	}
	if s := strings.ToUpper(strings.TrimSpace(maxSev)); s != "" {
		return s
	}
	return severityFromScore(maxScore)
}

func severityFromScore(s float64) string {
	switch {
	case s >= 9.0:
		return "CRITICAL"
	case s >= 7.0:
		return "HIGH"
	case s >= 4.0:
		return "MEDIUM"
	case s > 0:
		return "LOW"
	default:
		return "NONE"
	}
}

func reverseDependents(links []GraphLink) map[string][]string {
	out := make(map[string][]string)
	for _, l := range links {
		t := strings.TrimSpace(l.Target)
		s := strings.TrimSpace(l.Source)
		if t == "" || s == "" {
			continue
		}
		out[t] = append(out[t], s)
	}
	return out
}

func forwardDeps(links []GraphLink) map[string][]string {
	out := make(map[string][]string)
	for _, l := range links {
		s := strings.TrimSpace(l.Source)
		t := strings.TrimSpace(l.Target)
		if s == "" || t == "" {
			continue
		}
		out[s] = append(out[s], t)
	}
	return out
}

// blastRadius counts distinct packages that transitively depend on id (reverse BFS from id).
func blastRadius(id string, rev map[string][]string) int {
	seen := map[string]struct{}{id: {}}
	q := []string{id}
	count := 0
	for head := 0; head < len(q); head++ {
		cur := q[head]
		for _, d := range rev[cur] {
			if _, ok := seen[d]; ok {
				continue
			}
			seen[d] = struct{}{}
			count++
			q = append(q, d)
		}
	}
	return count
}

func subtreeContainsCVE(id string, fwd map[string][]string, direct map[string]bool, memo, visiting map[string]bool) bool {
	if v, ok := memo[id]; ok {
		return v
	}
	if visiting[id] {
		return false
	}
	visiting[id] = true
	defer delete(visiting, id)
	if direct[id] {
		memo[id] = true
		return true
	}
	for _, c := range fwd[id] {
		if subtreeContainsCVE(c, fwd, direct, memo, visiting) {
			memo[id] = true
			return true
		}
	}
	memo[id] = false
	return false
}

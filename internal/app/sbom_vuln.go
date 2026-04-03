package app

import "strings"

// IndexVulnerabilitiesByRef maps each component ref (from vulnerability affects[].ref, e.g. bom-ref or purl)
// to the CycloneDX vulnerability entries that list that ref. One vulnerability may appear under multiple keys.
func IndexVulnerabilitiesByRef(s *SBOM) map[string][]Vulnerability {
	// If the SBOM is nil, return nil
	if s == nil {
		return nil
	}

	// Initialize the map
	out := make(map[string][]Vulnerability)

	// Loop through the vulnerabilities
	for _, v := range s.Vulnerabilities {
		// Loop through the affects
		for _, a := range v.Affects {
			// Trim the reference
			ref := strings.TrimSpace(a.Ref)
			if ref == "" {
				continue
			}
			// Append the vulnerability to the map
			out[ref] = append(out[ref], v)
		}
	}

	return out
}

// vulnerabilityToCVEEntry picks the highest-scoring rating and maps it to CVEEntry for graph enrichment.
func vulnerabilityToCVEEntry(v Vulnerability) CVEEntry {
	e := CVEEntry{ID: strings.TrimSpace(v.ID)}
	var best float64
	var bestSev string
	for _, r := range v.Ratings {
		if r.Score > best {
			best = r.Score
			bestSev = strings.TrimSpace(r.Severity)
		}
	}
	e.BaseScore = best
	e.BaseSeverity = strings.ToUpper(bestSev)
	if e.BaseSeverity == "MODERATE" {
		e.BaseSeverity = "MEDIUM"
	}
	return e
}

// refToCVEEntriesFromSBOM converts CycloneDX vulnerabilities into a ref → CVE rows map (deduped by CVE id per ref).
func refToCVEEntriesFromSBOM(sbom *SBOM) map[string][]CVEEntry {
	if sbom == nil {
		return nil
	}
	idx := IndexVulnerabilitiesByRef(sbom)
	out := make(map[string][]CVEEntry, len(idx))
	for ref, vulns := range idx {
		seen := make(map[string]struct{})
		var list []CVEEntry
		for _, v := range vulns {
			id := strings.TrimSpace(v.ID)
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			list = append(list, vulnerabilityToCVEEntry(v))
		}
		if len(list) > 0 {
			out[ref] = list
		}
	}
	return out
}

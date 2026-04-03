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

package app

import (
	"path/filepath"
	"runtime"
	"testing"
)

// TestIndexVulnerabilitiesByRef_sbomWithCVEs tests the IndexVulnerabilitiesByRef function with a SBOM that contains CVEs
func TestIndexVulnerabilitiesByRef_sbomWithCVEs(t *testing.T) {
	// Get the root directory of the project
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	path := filepath.Join(root, "testdata", "sbom-with-cves.json")

	// Load the SBOM
	sbom, err := LoadSBOM(path)
	if err != nil {
		t.Fatal(err)
	}

	// Index the vulnerabilities by reference
	idx := IndexVulnerabilitiesByRef(sbom)

	// Get the vulnerabilities for the reference
	ref := "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	list := idx[ref]
	if len(list) == 0 {
		t.Fatalf("no vulnerabilities for ref %q", ref)
	}

	// Check if the CVE-2021-44228 is in the list
	var saw44228 bool
	// Loop through the vulnerabilities
	for _, v := range list {
		if v.ID == "CVE-2021-44228" {
			saw44228 = true
			break
		}
	}
	if !saw44228 {
		t.Fatalf("expected CVE-2021-44228 in index for %q, got %d entries", ref, len(list))
	}
}

// TestCVESForComponent_aliasMatch ensures affects keyed only by purl still attach when graph uses bom-ref as canonical Ref.
func TestCVESForComponent_aliasMatch(t *testing.T) {
	refCVEs := map[string][]CVEEntry{
		"pkg:npm/foo@1.0.0": {{ID: "CVE-2020-1", BaseScore: 7.0, BaseSeverity: "HIGH"}},
	}
	c := Component{BOMRef: "npm-foo-1", PURL: "pkg:npm/foo@1.0.0", Name: "foo", Version: "1.0.0"}
	out := cvesForComponent(refCVEs, c)
	if len(out) != 1 || out[0].ID != "CVE-2020-1" {
		t.Fatalf("got %+v", out)
	}
}

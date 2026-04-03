/*
This file is responsible for loading the SBOM and parsing it into a struct.
It is used to build the dependency graph and the web UI.
*/

package app

import (
	"encoding/json"
	"io"
	"os"
	"strings"
)

// SBOM is the root object of the SBOM
type SBOM struct {
	BOMFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	// SerialNumber string   `json:"serialNumber"`
	// Version  int8     `json:"version"`
	Metadata        Metadata        `json:"metadata"`
	Components      []Component     `json:"components,omitempty"`
	Dependencies    []Dependency    `json:"dependencies,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

// Vulnerability is one entry in CycloneDX top-level vulnerabilities[] (e.g. 1.4–1.7).
// Unknown JSON keys still decode fine. omitempty is used on scalars and slices; struct-valued
// fields omit omitempty because encoding/json only treats the whole struct as “empty”, not each inner field.
type Vulnerability struct {
	BOMRef      string                `json:"bom-ref,omitempty"`
	ID          string                `json:"id,omitempty"`
	Source      VulnerabilitySource   `json:"source"`
	Description string                `json:"description,omitempty"`
	Ratings     []VulnerabilityRating `json:"ratings,omitempty"`
	Affects     []VulnerabilityAffect `json:"affects,omitempty"`
}

// VulnerabilitySource identifies who reported the vulnerability (e.g. NVD).
type VulnerabilitySource struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

// VulnerabilityRating holds a score/severity (often CVSS).
type VulnerabilityRating struct {
	Source   VulnerabilitySource `json:"source"`
	Score    float64             `json:"score,omitempty"`
	Severity string              `json:"severity,omitempty"`
	Method   string              `json:"method,omitempty"`
}

// VulnerabilityAffect links a vulnerability to a component via ref (bom-ref or purl).
type VulnerabilityAffect struct {
	Ref string `json:"ref,omitempty"`
}

// Metadata is the metadata object of the SBOM
type Metadata struct {
	// Timestamp string    `json:"timestamp"`
	// Tools     []Tool    `json:"tools"`
	Component Component `json:"component"`
}

// Tool is the tool object of the SBOM
type Tool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Component is the component object of the SBOM
type Component struct {
	Type    string `json:"type"`
	BOMRef  string `json:"bom-ref"`
	Name    string `json:"name"`
	Version string `json:"version"`
	// Description        string              `json:"description"`
	// Licenses           []string            `json:"licenses"`
	PURL string `json:"purl"` // Package URL
	// ExternalReferences []ExternalReference `json:"externalReferences"`
}

type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

// ExternalReference represents an external resource related to the component,
// such as a website, issue tracker, or version control system URL that offers
// additional information about the component.
type ExternalReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// DecodeSBOM decodes CycloneDX JSON from r.
func DecodeSBOM(r io.Reader) (*SBOM, error) {
	var s SBOM
	if err := json.NewDecoder(r).Decode(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

// LoadSBOM reads and decodes a CycloneDX JSON file from disk.
func LoadSBOM(path string) (*SBOM, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return DecodeSBOM(f)
}

// Ref returns the canonical dependency-graph id: bom-ref if set, otherwise purl.
func (c Component) Ref() string {
	if s := strings.TrimSpace(c.BOMRef); s != "" {
		return s
	}
	return strings.TrimSpace(c.PURL)
}

// AdjacencyList maps each dependency ref to the components it depends on.
func AdjacencyList(s *SBOM) map[string][]string {
	out := make(map[string][]string, len(s.Dependencies))
	for _, d := range s.Dependencies {
		out[d.Ref] = d.DependsOn
	}
	return out
}

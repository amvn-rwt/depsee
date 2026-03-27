package main

import (
	"encoding/json"
	"os"
	"strings"
)

// SBOM is the root object of the SBOM
type SBOM struct {
	BOMFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	// SerialNumber string   `json:"serialNumber"`
	// Version  int8     `json:"version"`
	Metadata     Metadata     `json:"metadata"`
	Components   []Component  `json:"components"`
	Dependencies []Dependency `json:"dependencies"`
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

// LoadSBOM reads and decodes a CycloneDX JSON file from disk.
func LoadSBOM(path string) (*SBOM, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var s SBOM
	if err := json.NewDecoder(f).Decode(&s); err != nil {
		return nil, err
	}
	return &s, nil
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

package main

import (
	"fmt"
	"strings"
)

// ParsedPURL holds the parts of a package URL we need for CPE and NVD queries.
// See https://github.com/package-url/purl-spec
type ParsedPURL struct {
	Type      string
	Namespace string
	Name      string
	Version   string
}

// ParsePURL parses a Package URL (scheme pkg:). Qualifiers and subpath are ignored.
func ParsePURL(raw string) (ParsedPURL, error) {
	s := strings.TrimSpace(raw)

	if s == "" {
		return ParsedPURL{}, fmt.Errorf("empty purl")
	}

	if !strings.HasPrefix(s, "pkg:") {
		return ParsedPURL{}, fmt.Errorf("purl must start with pkg:")
	}

	rest := s[4:]
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}

	var version string
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		version = rest[at+1:]
		rest = rest[:at]
	}

	before, after, found := strings.Cut(rest, "/")
	if !found {
		return ParsedPURL{Type: rest, Version: version}, nil
	}

	typ := before
	path := after

	if path == "" {
		return ParsedPURL{Type: typ, Version: version}, nil
	}

	lastSlash := strings.LastIndex(path, "/")
	var namespace, name string
	if lastSlash < 0 {
		name = path
	} else {
		namespace = path[:lastSlash]
		name = path[lastSlash+1:]
	}

	return ParsedPURL{
		Type:      typ,
		Namespace: namespace,
		Name:      name,
		Version:   version,
	}, nil
}

// ProductNameForCPE returns a single product string for CPE (npm scoped → "scope/name").
func (p ParsedPURL) ProductNameForCPE() string {
	ns := strings.TrimSpace(p.Namespace)
	nm := strings.TrimSpace(p.Name)

	if ns == "" {
		return nm
	}

	// Strip leading @ from scope for readability; CPE escaping handles the rest.
	ns = strings.TrimPrefix(ns, "@")
	if ns == "" {
		return nm
	}

	return ns + "/" + nm
}

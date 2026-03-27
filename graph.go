package main

import (
	"fmt"
	"sort"
	"strings"
)

// Graph is the payload for /api/graph and D3 (nodes + directed links).
type Graph struct {
	Nodes []GraphNode `json:"nodes"`
	Links []GraphLink `json:"links"`
}

// GraphNode is one vertex in the dependency graph (ref = stable id).
type GraphNode struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Type    string `json:"type"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// GraphLink is a directed edge: dependent (source) → dependency (target).
type GraphLink struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

// BuildGraph derives nodes and edges from CycloneDX components and dependencies.
func BuildGraph(s *SBOM) *Graph {
	refToComp := indexComponents(s)
	nodeIDs := make(map[string]struct{})
	var links []GraphLink
	linkSeen := make(map[string]struct{})

	for _, d := range s.Dependencies {
		src := strings.TrimSpace(d.Ref)
		if src != "" {
			nodeIDs[src] = struct{}{}
		}
		for _, raw := range d.DependsOn {
			tgt := strings.TrimSpace(raw)
			if tgt == "" || src == "" {
				continue
			}
			nodeIDs[tgt] = struct{}{}
			key := src + "\x00" + tgt
			if _, dup := linkSeen[key]; dup {
				continue
			}
			linkSeen[key] = struct{}{}
			links = append(links, GraphLink{Source: src, Target: tgt})
		}
	}

	for ref := range refToComp {
		nodeIDs[ref] = struct{}{}
	}

	ids := make([]string, 0, len(nodeIDs))
	for id := range nodeIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	nodes := make([]GraphNode, 0, len(ids))
	for _, id := range ids {
		n := GraphNode{ID: id, Label: id}
		if c, ok := refToComp[id]; ok {
			n.Type = c.Type
			n.Name = strings.TrimSpace(c.Name)
			n.Version = strings.TrimSpace(c.Version)
			switch {
			case n.Name != "" && n.Version != "":
				n.Label = fmt.Sprintf("%s@%s", n.Name, n.Version)
			case n.Name != "":
				n.Label = n.Name
			case n.Version != "":
				n.Label = n.Version
			default:
				n.Label = id
			}
		}
		nodes = append(nodes, n)
	}

	sort.Slice(links, func(i, j int) bool {
		if links[i].Source != links[j].Source {
			return links[i].Source < links[j].Source
		}
		return links[i].Target < links[j].Target
	})

	return &Graph{Nodes: nodes, Links: links}
}

// indexComponents maps each component's BOMRef to its Component struct.
func indexComponents(s *SBOM) map[string]Component {
	out := make(map[string]Component)
	if ref := s.Metadata.Component.Ref(); ref != "" {
		out[ref] = s.Metadata.Component
	}
	for _, c := range s.Components {
		if ref := c.Ref(); ref != "" {
			out[ref] = c
		}
	}
	return out
}

//TODO: SBOM changes depending upon the spec version

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func main() {
	jsonFile, err := os.Open("testdata/sbom.json")
	if err != nil {
		fmt.Printf("Error opening JSON file: %v\n", err)
		os.Exit(1)
	}

	defer jsonFile.Close()

	var sbom SBOM
	if err := json.NewDecoder(jsonFile).Decode(&sbom); err != nil {
		fmt.Printf("Error decoding JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("app - %s:%s \n", sbom.Metadata.Component.Name, sbom.Metadata.Component.Version)
	fmt.Printf("format - %s:%s \n", sbom.BOMFormat, sbom.SpecVersion)
	fmt.Printf("packages - found: %d \n", len(sbom.Components))
	fmt.Println("--------------------------------")

	// Build the adjacency list
	adjacencyList := buildAdjacencyList(sbom)

	// Print the adjacency list
	for pkg, dependencies := range adjacencyList {
		fmt.Printf("%s -> %s \n", pkg, strings.Join(dependencies, " | "))
		fmt.Println()
	}
}

func buildAdjacencyList(sbom SBOM) map[string][]string {
	adjacencyList := make(map[string][]string)
	for _, dependency := range sbom.Dependencies {
		adjacencyList[dependency.Ref] = dependency.DependsOn
	}
	return adjacencyList
}

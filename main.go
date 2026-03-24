//TODO: SBOM changes depending upon the spec version

package main

import (
	"encoding/json"
	"fmt"
	"os"
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

	for _, component := range sbom.Components {
		fmt.Printf("package -> %s:%s \n", component.Name, component.Version)
	}
}

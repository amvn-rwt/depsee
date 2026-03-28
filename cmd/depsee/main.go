package main

import (
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/amvn-rwt/depsee/internal/app"
)

func main() {
	serve := flag.Bool("serve", false, "serve web UI over HTTP")
	addr := flag.String("addr", ":8080", "HTTP listen address (with -serve)")
	file := flag.String("file", "testdata/min-sbom.json", "path to CycloneDX SBOM JSON")
	skipNVD := flag.Bool("skip-nvd", false, "skip NVD CVE enrichment (no network; use with -serve)")
	flag.Parse()

	if *serve {
		app.RunWebServer(*addr, *file, *skipNVD)
		return
	}

	if err := runCLI(*file); err != nil {
		log.Fatal(err)
	}
}

func runCLI(sbomPath string) error {
	sbom, err := app.LoadSBOM(sbomPath)
	if err != nil {
		return err
	}

	fmt.Printf("app - %s:%s\n", sbom.Metadata.Component.Name, sbom.Metadata.Component.Version)
	fmt.Printf("format - %s %s\n", sbom.BOMFormat, sbom.SpecVersion)
	fmt.Printf("packages - %d\n", len(sbom.Components))
	fmt.Println("--------------------------------")

	adj := app.AdjacencyList(sbom)
	for ref, deps := range adj {
		fmt.Printf("%s -> %s\n", ref, strings.Join(deps, " | "))
		fmt.Println()
	}
	return nil
}

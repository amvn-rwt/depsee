package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
)

//go:embed web
var webFS embed.FS

func runWebServer(addr, sbomPath string) {
	sbom, err := LoadSBOM(sbomPath)
	if err != nil {
		log.Fatalf("load SBOM %q: %v", sbomPath, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/graph", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err := json.NewEncoder(w).Encode(BuildGraph(sbom)); err != nil {
			log.Printf("encode /api/graph: %v", err)
		}
	})

	root, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("/", http.FileServer(http.FS(root)))

	log.Printf("depsee web UI at http://127.0.0.1%s/ (SBOM: %s)", addr, sbomPath)
	log.Fatal(http.ListenAndServe(addr, mux))
}

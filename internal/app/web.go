package app

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"
)

//go:embed web
var webFS embed.FS

func RunWebServer(addr, sbomPath string, skipNVD bool) {
	sbom, err := LoadSBOM(sbomPath)
	if err != nil {
		log.Fatalf("load SBOM %q: %v", sbomPath, err)
	}

	g := BuildGraph(sbom)
	if !skipNVD {
		nvd := NewNVDClient(os.Getenv("NVD_API_KEY"))
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		if err := EnrichGraph(ctx, sbom, g, nvd); err != nil {
			log.Printf("NVD enrichment: %v", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/graph", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err := json.NewEncoder(w).Encode(g); err != nil {
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

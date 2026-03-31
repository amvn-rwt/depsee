package app

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"
)

//go:embed web
var webFS embed.FS

// maxSBOMUploadBytes caps POST /api/sbom body size (JSON or multipart file).
const maxSBOMUploadBytes = 32 << 20 // 32 MiB

func RunWebServer(addr, sbomPath string, skipNVD bool) {
	sbom, err := LoadSBOM(sbomPath)
	if err != nil {
		log.Fatalf("load SBOM %q: %v", sbomPath, err)
	}

	g := BuildGraph(sbom)
	enrichGraphIfConfigured(sbom, g, skipNVD)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/graph", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err := json.NewEncoder(w).Encode(g); err != nil {
			log.Printf("encode /api/graph: %v", err)
		}
	})
	mux.HandleFunc("POST /api/sbom", func(w http.ResponseWriter, r *http.Request) {
		handlePostSBOM(w, r, skipNVD)
	})

	root, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("/", http.FileServer(http.FS(root)))

	log.Printf("depsee web UI at http://127.0.0.1%s/ (SBOM: %s)", addr, sbomPath)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// enrichGraphIfConfigured enriches the graph with NVD data if configured.
func enrichGraphIfConfigured(sbom *SBOM, g *Graph, skipNVD bool) {
	// If NVD enrichment is disabled, return.
	if skipNVD {
		return
	}

	// Create a NVD client.
	nvd := NewNVDClient(os.Getenv("NVD_API_KEY"))

	// Create a context with a timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// Enrich the graph with NVD data.
	if err := EnrichGraph(ctx, sbom, g, nvd); err != nil {
		log.Printf("NVD enrichment: %v", err)
	}
}

// handlePostSBOM handles the POST /api/sbom endpoint.
// It decodes the SBOM from the request body and builds the dependency graph.
// It then enriches the graph with NVD data if configured. It returns the graph as a JSON response.
func handlePostSBOM(w http.ResponseWriter, r *http.Request, skipNVD bool) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	r.Body = http.MaxBytesReader(w, r.Body, maxSBOMUploadBytes)

	ct := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid Content-Type")
		return
	}

	var sbom *SBOM
	switch {
	case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
		sbom, err = DecodeSBOM(r.Body)
	case mediaType == "multipart/form-data":
		if err := r.ParseMultipartForm(maxSBOMUploadBytes); err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				writeJSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
				return
			}
			writeJSONError(w, http.StatusBadRequest, "invalid multipart form")
			return
		}
		f, fh, ferr := r.FormFile("file")
		if ferr != nil {
			writeJSONError(w, http.StatusBadRequest, "missing form field \"file\"")
			return
		}
		defer f.Close()
		if fh.Size >= 0 && fh.Size > maxSBOMUploadBytes {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "file too large")
			return
		}
		sbom, err = DecodeSBOM(f)
	default:
		writeJSONError(w, http.StatusUnsupportedMediaType, "use application/json or multipart/form-data with field \"file\"")
		return
	}

	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			writeJSONError(w, http.StatusBadRequest, "empty or truncated body")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "invalid CycloneDX JSON")
		return
	}

	g := BuildGraph(sbom)
	enrichGraphIfConfigured(sbom, g, skipNVD)

	if err := json.NewEncoder(w).Encode(g); err != nil {
		log.Printf("encode POST /api/sbom: %v", err)
	}
}

// apiError is the error response for the API.
type apiError struct {
	Error string `json:"error"`
}

// writeJSONError writes a JSON error response to the http.ResponseWriter.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(apiError{Error: msg})
}

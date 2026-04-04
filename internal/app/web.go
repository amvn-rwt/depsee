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
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

//go:embed web
var webFS embed.FS

// maxSBOMUploadBytes caps POST /api/sbom body size (JSON or multipart file).
const maxSBOMUploadBytes = 32 << 20 // 32 MiB

// httpDisplayURL returns a copy-pasteable http URL for logging when the server
// listens on addr. Go's convention ":8080" means all interfaces; we show 127.0.0.1
// so users open the UI locally. Host:port addrs (e.g. "127.0.0.1:9090") are used as-is.
func httpDisplayURL(addr string) string {
	a := strings.TrimSpace(addr)
	if a == "" {
		return "http://127.0.0.1:8080"
	}
	if strings.HasPrefix(a, ":") {
		return "http://127.0.0.1" + a
	}
	return "http://" + a
}

// httpURLFromListenAddr builds a local http URL from net.Listener.Addr().String().
// Wildcard binds (0.0.0.0, ::) map to 127.0.0.1 so the link works in a browser.
func httpURLFromListenAddr(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return httpDisplayURL(listen)
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		return "http://127.0.0.1:" + port
	default:
		return "http://" + net.JoinHostPort(host, port)
	}
}

func RunWebServer(addr, sbomPath string, skipNVD, openBrowser bool) {
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
	mux.HandleFunc("GET /api/jobs/{id}", handleGetSBOMJob)

	root, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("/", http.FileServer(http.FS(root)))

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen %q: %v", addr, err)
	}
	baseURL := httpURLFromListenAddr(ln.Addr().String())
	if openBrowser {
		u := baseURL + "/"
		go func() {
			time.Sleep(150 * time.Millisecond)
			if err := OpenDefaultBrowser(u); err != nil {
				log.Printf("open browser: %v", err)
			}
		}()
	}
	log.Printf("depsee web UI at %s/ (SBOM: %s)", baseURL, sbomPath)
	log.Fatal(http.Serve(ln, mux))
}

// enrichGraphIfConfigured attaches CVE data from CycloneDX vulnerabilities[], then optionally merges NVD when skipNVD is false.
func enrichGraphIfConfigured(sbom *SBOM, g *Graph, skipNVD bool) {
	refCVEs := refToCVEEntriesFromSBOM(sbom)
	if skipNVD {
		applyRefCVEsAndAnalyze(sbom, g, refCVEs)
		return
	}

	nvd := NewNVDClient(os.Getenv("NVD_API_KEY"))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	if err := mergeNVDCVEsIntoRefMap(ctx, sbom, g, nvd, refCVEs, nil); err != nil {
		log.Printf("NVD enrichment: %v", err)
	}
	applyRefCVEsAndAnalyze(sbom, g, refCVEs)
}

// readSBOMUploadPayload reads raw CycloneDX JSON from a POST body (JSON or multipart field "file").
// It writes JSON errors to w and returns ok false on failure.
func readSBOMUploadPayload(w http.ResponseWriter, r *http.Request) (raw []byte, ok bool) {
	ct := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid Content-Type")
		return nil, false
	}

	switch {
	case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
		var err error
		raw, err = io.ReadAll(r.Body)
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				writeJSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
				return nil, false
			}
			writeJSONError(w, http.StatusBadRequest, "invalid body")
			return nil, false
		}
		if len(raw) == 0 {
			writeJSONError(w, http.StatusBadRequest, "empty body")
			return nil, false
		}
		return raw, true

	case mediaType == "multipart/form-data":
		if err := r.ParseMultipartForm(maxSBOMUploadBytes); err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				writeJSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
				return nil, false
			}
			writeJSONError(w, http.StatusBadRequest, "invalid multipart form")
			return nil, false
		}
		f, fh, ferr := r.FormFile("file")
		if ferr != nil {
			writeJSONError(w, http.StatusBadRequest, "missing form field \"file\"")
			return nil, false
		}
		defer f.Close()
		if fh.Size >= 0 && fh.Size > maxSBOMUploadBytes {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "file too large")
			return nil, false
		}
		raw, err := io.ReadAll(f)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "could not read file")
			return nil, false
		}
		if len(raw) == 0 {
			writeJSONError(w, http.StatusBadRequest, "empty file")
			return nil, false
		}
		return raw, true

	default:
		writeJSONError(w, http.StatusUnsupportedMediaType, "use application/json or multipart/form-data with field \"file\"")
		return nil, false
	}
}

// handlePostSBOM accepts CycloneDX JSON and starts background processing.
// It responds with 202 Accepted and {"jobId":"..."}; poll GET /api/jobs/{id} for the graph.
func handlePostSBOM(w http.ResponseWriter, r *http.Request, skipNVD bool) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	r.Body = http.MaxBytesReader(w, r.Body, maxSBOMUploadBytes)

	raw, ok := readSBOMUploadPayload(w, r)
	if !ok {
		return
	}

	jobID, err := registerSBOMJob()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "could not create job")
		return
	}
	go startSBOMJob(jobID, raw, skipNVD)

	w.WriteHeader(http.StatusAccepted)
	if err := json.NewEncoder(w).Encode(struct {
		JobID string `json:"jobId"`
	}{JobID: jobID}); err != nil {
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

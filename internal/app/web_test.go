package app

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandlePostSBOM_JSON(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "min-sbom.json"))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/sbom", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handlePostSBOM(rec, req, true)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
	var g Graph
	if err := json.NewDecoder(rec.Body).Decode(&g); err != nil {
		t.Fatal(err)
	}
	if len(g.Nodes) == 0 {
		t.Fatal("expected nodes")
	}
}

func TestHandlePostSBOM_multipartFile(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "min-sbom.json"))
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("file", "sbom.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/sbom", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()
	handlePostSBOM(rec, req, true)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
}

func TestHandlePostSBOM_unsupportedMediaType(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/sbom", strings.NewReader("x"))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	handlePostSBOM(rec, req, true)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("want 415, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandlePostSBOM_invalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/sbom", strings.NewReader(`{`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handlePostSBOM(rec, req, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

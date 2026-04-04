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
	"time"
)

type jobCreatedResp struct {
	JobID string `json:"jobId"`
}

func pollSBOMJob(t *testing.T, jobID string, maxWait time.Duration) SBOMJob {
	t.Helper()
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		req := httptest.NewRequest(http.MethodGet, "/api/jobs/"+jobID, nil)
		req.SetPathValue("id", jobID)
		rec := httptest.NewRecorder()
		handleGetSBOMJob(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET job: status %d body %s", rec.Code, rec.Body.String())
		}
		var job SBOMJob
		if err := json.NewDecoder(rec.Body).Decode(&job); err != nil {
			t.Fatal(err)
		}
		switch job.Status {
		case SBOMJobStatusCompleted, SBOMJobStatusFailed:
			return job
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("job did not finish in time")
	return SBOMJob{}
}

func TestHTTPDisplayURL(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{":8080", "http://127.0.0.1:8080"},
		{"127.0.0.1:18080", "http://127.0.0.1:18080"},
		{"localhost:9090", "http://localhost:9090"},
		{"0.0.0.0:3000", "http://0.0.0.0:3000"},
		{"[::1]:8080", "http://[::1]:8080"},
		{"  :4000  ", "http://127.0.0.1:4000"},
		{"", "http://127.0.0.1:8080"},
	}
	for _, tc := range tests {
		if got := httpDisplayURL(tc.addr); got != tc.want {
			t.Errorf("httpDisplayURL(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

func TestHandlePostSBOM_JSON(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "min-sbom.json"))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/sbom", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handlePostSBOM(rec, req, true)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
	var created jobCreatedResp
	if err := json.NewDecoder(rec.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.JobID == "" {
		t.Fatal("empty jobId")
	}
	job := pollSBOMJob(t, created.JobID, 2*time.Second)
	if job.Status != SBOMJobStatusCompleted {
		t.Fatalf("job failed: %+v", job)
	}
	if job.Graph == nil || len(job.Graph.Nodes) == 0 {
		t.Fatal("expected graph nodes")
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

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
	var created jobCreatedResp
	if err := json.NewDecoder(rec.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	job := pollSBOMJob(t, created.JobID, 2*time.Second)
	if job.Status != SBOMJobStatusCompleted {
		t.Fatalf("job failed: %+v", job)
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
	if rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var created jobCreatedResp
	if err := json.NewDecoder(rec.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	job := pollSBOMJob(t, created.JobID, 2*time.Second)
	if job.Status != SBOMJobStatusFailed {
		t.Fatalf("want failed job, got %+v", job)
	}
	if job.Error == "" {
		t.Fatal("expected error message")
	}
}

func TestHandleGetSBOMJob_notFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/jobs/nope", nil)
	req.SetPathValue("id", "nope")
	rec := httptest.NewRecorder()
	handleGetSBOMJob(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

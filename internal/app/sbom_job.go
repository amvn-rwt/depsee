package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// SBOMJobPhase is a coarse processing stage for UI progress.
type SBOMJobPhase string

const (
	SBOMJobPhaseQueued        SBOMJobPhase = "queued"
	SBOMJobPhaseParsing       SBOMJobPhase = "parsing"
	SBOMJobPhaseBuilding      SBOMJobPhase = "building"
	SBOMJobPhaseEnriching     SBOMJobPhase = "enriching"
	SBOMJobPhaseAggregating   SBOMJobPhase = "aggregating"
	SBOMJobPhaseDone          SBOMJobPhase = "done"
)

// SBOMJobStatus is the lifecycle state of a job.
type SBOMJobStatus string

const (
	SBOMJobStatusPending   SBOMJobStatus = "pending"
	SBOMJobStatusRunning   SBOMJobStatus = "running"
	SBOMJobStatusCompleted SBOMJobStatus = "completed"
	SBOMJobStatusFailed    SBOMJobStatus = "failed"
)

// SBOMJob is returned by GET /api/jobs/{id} and stored in the in-memory registry.
type SBOMJob struct {
	JobID   string        `json:"jobId"`
	Status  SBOMJobStatus `json:"status"`
	Phase   SBOMJobPhase  `json:"phase"`
	Percent float64       `json:"percent"`
	Error   string        `json:"error,omitempty"`
	Graph   *Graph        `json:"graph,omitempty"`
}

type sbomJobEntry struct {
	mu  sync.RWMutex
	job SBOMJob
}

var (
	sbomJobMu    sync.Mutex
	sbomJobByID = make(map[string]*sbomJobEntry)
)

// newSBOMJobID returns a random hex job identifier.
func newSBOMJobID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// startSBOMJob decodes raw CycloneDX JSON, builds the graph, optionally enriches, and updates the job entry.
func startSBOMJob(jobID string, rawJSON []byte, skipNVD bool) {
	entry := getSBOMJobEntry(jobID)
	if entry == nil {
		return
	}

	entry.mu.Lock()
	entry.job.Status = SBOMJobStatusRunning
	entry.job.Phase = SBOMJobPhaseParsing
	entry.job.Percent = 5
	entry.mu.Unlock()

	sbom, err := DecodeSBOM(bytes.NewReader(rawJSON))
	if err != nil {
		failSBOMJob(jobID, SBOMJobPhaseParsing, "invalid CycloneDX JSON")
		return
	}

	entry.mu.Lock()
	entry.job.Phase = SBOMJobPhaseBuilding
	entry.job.Percent = 15
	entry.mu.Unlock()

	g := BuildGraph(sbom)

	if skipNVD {
		completeSBOMJob(jobID, g)
		return
	}

	entry.mu.Lock()
	entry.job.Phase = SBOMJobPhaseEnriching
	entry.job.Percent = 20
	entry.mu.Unlock()

	nvd := NewNVDClient(os.Getenv("NVD_API_KEY"))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	onProgress := func(done, total int) {
		if total <= 0 {
			return
		}
		pct := 20 + 70*float64(done)/float64(total)
		if pct > 90 {
			pct = 90
		}
		updateSBOMJobProgress(jobID, SBOMJobPhaseEnriching, pct)
	}

	if err := EnrichGraph(ctx, sbom, g, nvd, onProgress); err != nil {
		log.Printf("job %s NVD enrichment: %v", jobID, err)
	}

	entry.mu.Lock()
	entry.job.Phase = SBOMJobPhaseAggregating
	entry.job.Percent = 95
	entry.mu.Unlock()

	completeSBOMJob(jobID, g)
}

func getSBOMJobEntry(id string) *sbomJobEntry {
	sbomJobMu.Lock()
	defer sbomJobMu.Unlock()
	return sbomJobByID[id]
}

func failSBOMJob(jobID string, phase SBOMJobPhase, msg string) {
	entry := getSBOMJobEntry(jobID)
	if entry == nil {
		return
	}
	entry.mu.Lock()
	entry.job.Status = SBOMJobStatusFailed
	entry.job.Phase = phase
	entry.job.Error = msg
	entry.mu.Unlock()
}

func updateSBOMJobProgress(jobID string, phase SBOMJobPhase, percent float64) {
	entry := getSBOMJobEntry(jobID)
	if entry == nil {
		return
	}
	entry.mu.Lock()
	entry.job.Phase = phase
	entry.job.Percent = percent
	entry.mu.Unlock()
}

func completeSBOMJob(jobID string, g *Graph) {
	entry := getSBOMJobEntry(jobID)
	if entry == nil {
		return
	}
	entry.mu.Lock()
	entry.job.Status = SBOMJobStatusCompleted
	entry.job.Phase = SBOMJobPhaseDone
	entry.job.Percent = 100
	entry.job.Graph = g
	entry.job.Error = ""
	entry.mu.Unlock()
}

// registerSBOMJob creates a pending job and returns its id.
func registerSBOMJob() (string, error) {
	id, err := newSBOMJobID()
	if err != nil {
		return "", err
	}
	entry := &sbomJobEntry{
		job: SBOMJob{
			JobID:   id,
			Status:  SBOMJobStatusPending,
			Phase:   SBOMJobPhaseQueued,
			Percent: 0,
		},
	}
	sbomJobMu.Lock()
	sbomJobByID[id] = entry
	sbomJobMu.Unlock()
	return id, nil
}

// snapshotSBOMJob returns a copy of the job for JSON encoding.
func snapshotSBOMJob(id string) (SBOMJob, bool) {
	sbomJobMu.Lock()
	entry, ok := sbomJobByID[id]
	sbomJobMu.Unlock()
	if !ok {
		return SBOMJob{}, false
	}
	entry.mu.RLock()
	defer entry.mu.RUnlock()
	return entry.job, true
}

// handleGetSBOMJob serves GET /api/jobs/{id}.
func handleGetSBOMJob(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	id := r.PathValue("id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "missing job id")
		return
	}
	job, ok := snapshotSBOMJob(id)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "job not found")
		return
	}
	if err := json.NewEncoder(w).Encode(job); err != nil {
		log.Printf("encode GET /api/jobs: %v", err)
	}
}

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const defaultNVDBase = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// CVEEntry is a minimal CVE row for graph enrichment (from NVD and/or CycloneDX vulnerabilities).
type CVEEntry struct {
	ID           string
	BaseScore    float64
	BaseSeverity string // CVSS 3.x qualitative severity when present
}

// NVDClient queries the NVD CVE API 2.0 with rate limiting, retries, and caching.
type NVDClient struct {
	HTTPClient *http.Client
	// BaseURL is the full CVE API URL stem (…/rest/json/cves/2.0). Empty means production NVD.
	BaseURL string
	APIKey  string
	limiter *rate.Limiter

	mu    sync.Mutex
	cache map[string][]CVEEntry // key: virtualMatchString
}

func (c *NVDClient) cveAPIStem() string {
	if c != nil {
		if s := strings.TrimSpace(c.BaseURL); s != "" {
			return strings.TrimRight(s, "/")
		}
	}
	return defaultNVDBase
}

// NewNVDClient returns a client. With a non-empty apiKey, the NVD limit is 50 req / 30s;
// without a key, 5 req / 30s (rolling window; we pace using token rate).
func NewNVDClient(apiKey string) *NVDClient {
	var lim *rate.Limiter
	if apiKey != "" {
		lim = rate.NewLimiter(rate.Limit(50.0/30.0), 1)
	} else {
		lim = rate.NewLimiter(rate.Limit(5.0/30.0), 1)
	}
	return &NVDClient{
		HTTPClient: http.DefaultClient,
		APIKey:     apiKey,
		limiter:    lim,
		cache:      make(map[string][]CVEEntry),
	}
}

// CVEsForPURL builds a virtualMatchString from the Package URL and fetches CVEs.
func (c *NVDClient) CVEsForPURL(ctx context.Context, purl string) ([]CVEEntry, error) {
	vms, err := VirtualMatchStringFromPURL(purl)
	if err != nil {
		return nil, err
	}
	return c.CVEsForVirtualMatchString(ctx, vms)
}

// CVEsForVirtualMatchString queries NVD with virtualMatchString (CPE match string).
func (c *NVDClient) CVEsForVirtualMatchString(ctx context.Context, vms string) ([]CVEEntry, error) {
	c.mu.Lock()
	if v, ok := c.cache[vms]; ok {
		c.mu.Unlock()
		return v, nil
	}
	c.mu.Unlock()

	const pageSize = 2000
	var all []CVEEntry
	startIndex := 0

	for {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}

		u, err := url.Parse(c.cveAPIStem())
		if err != nil {
			return nil, err
		}
		q := u.Query()
		q.Set("virtualMatchString", vms)
		q.Set("resultsPerPage", fmt.Sprintf("%d", pageSize))
		q.Set("startIndex", fmt.Sprintf("%d", startIndex))
		u.RawQuery = q.Encode()

		body, err := c.getWithRetry(ctx, u.String())
		if err != nil {
			return nil, err
		}

		var resp nvdCVEResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode nvd json: %w", err)
		}

		for _, item := range resp.Vulnerabilities {
			if e := parseNVDCVEItem(item); e != nil {
				all = append(all, *e)
			}
		}

		if resp.TotalResults == 0 || len(resp.Vulnerabilities) == 0 {
			break
		}
		if startIndex+len(resp.Vulnerabilities) >= resp.TotalResults {
			break
		}
		rpp := resp.ResultsPerPage
		if rpp <= 0 {
			rpp = pageSize
		}
		startIndex += rpp
	}

	c.mu.Lock()
	c.cache[vms] = all
	c.mu.Unlock()
	return all, nil
}

func (c *NVDClient) getWithRetry(ctx context.Context, rawURL string) ([]byte, error) {
	var lastErr error
	backoff := 300 * time.Millisecond
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		if c.APIKey != "" {
			req.Header.Set("apiKey", c.APIKey)
		}

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = err
			if !sleepBackoff(ctx, backoff) {
				return nil, ctx.Err()
			}
			backoff *= 2
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			if !sleepBackoff(ctx, backoff) {
				return nil, ctx.Err()
			}
			backoff *= 2
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("nvd: HTTP %d", resp.StatusCode)
			if !sleepBackoff(ctx, backoff) {
				return nil, ctx.Err()
			}
			backoff *= 2
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("nvd: HTTP %d: %s", resp.StatusCode, truncateBody(body))
		}
		return body, nil
	}
	return nil, fmt.Errorf("nvd: retries exhausted: %w", lastErr)
}

func sleepBackoff(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func truncateBody(b []byte) string {
	const max = 200
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "…"
}

type nvdCVEResponse struct {
	ResultsPerPage  int       `json:"resultsPerPage"`
	StartIndex      int       `json:"startIndex"`
	TotalResults    int       `json:"totalResults"`
	Vulnerabilities []nvdVuln `json:"vulnerabilities"`
}

type nvdVuln struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID      string `json:"id"`
	Metrics struct {
		CVSSMetricV31 []struct {
			CVSSData struct {
				BaseScore    float64 `json:"baseScore"`
				BaseSeverity string  `json:"baseSeverity"`
			} `json:"cvssData"`
		} `json:"cvssMetricV31"`
		CVSSMetricV30 []struct {
			CVSSData struct {
				BaseScore    float64 `json:"baseScore"`
				BaseSeverity string  `json:"baseSeverity"`
			} `json:"cvssData"`
		} `json:"cvssMetricV30"`
	} `json:"metrics"`
}

func parseNVDCVEItem(v nvdVuln) *CVEEntry {
	id := strings.TrimSpace(v.CVE.ID)
	if id == "" {
		return nil
	}
	e := &CVEEntry{ID: id}
	if m := v.CVE.Metrics.CVSSMetricV31; len(m) > 0 {
		e.BaseScore = m[0].CVSSData.BaseScore
		e.BaseSeverity = m[0].CVSSData.BaseSeverity
		return e
	}
	if m := v.CVE.Metrics.CVSSMetricV30; len(m) > 0 {
		e.BaseScore = m[0].CVSSData.BaseScore
		e.BaseSeverity = m[0].CVSSData.BaseSeverity
		return e
	}
	return e
}

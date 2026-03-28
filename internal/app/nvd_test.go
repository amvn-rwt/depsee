package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNVDClient_CVEsForVirtualMatchString_mock(t *testing.T) {
	const page1 = `{
  "resultsPerPage": 2000,
  "startIndex": 0,
  "totalResults": 1,
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2022-1234",
        "metrics": {
          "cvssMetricV31": [
            {
              "cvssData": {
                "baseScore": 7.5,
                "baseSeverity": "HIGH"
              }
            }
          ]
        }
      }
    }
  ]
}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/json/cves/2.0" {
			t.Errorf("path %s", r.URL.Path)
		}
		if r.URL.Query().Get("virtualMatchString") == "" {
			t.Error("missing virtualMatchString")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(page1))
	}))
	defer srv.Close()

	c := NewNVDClient("")
	c.HTTPClient = srv.Client()
	c.BaseURL = srv.URL + "/rest/json/cves/2.0"

	entries, err := c.CVEsForVirtualMatchString(context.Background(), "cpe:2.3:a:*:express:4.18.0:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != "CVE-2022-1234" || entries[0].BaseScore != 7.5 || entries[0].BaseSeverity != "HIGH" {
		t.Fatalf("unexpected entries: %+v", entries)
	}

	// cache hit — same handler should not be called again for same VMS (single request total)
	n2, err := c.CVEsForVirtualMatchString(context.Background(), "cpe:2.3:a:*:express:4.18.0:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatal(err)
	}
	if len(n2) != 1 {
		t.Fatalf("cache: got %d", len(n2))
	}
}

func TestNVDClient_CVEsForPURL(t *testing.T) {
	const page1 = `{
  "resultsPerPage": 2000,
  "startIndex": 0,
  "totalResults": 0,
  "vulnerabilities": []
}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(page1))
	}))
	defer srv.Close()

	c := NewNVDClient("")
	c.HTTPClient = srv.Client()
	c.BaseURL = srv.URL + "/rest/json/cves/2.0"

	_, err := c.CVEsForPURL(context.Background(), "pkg:npm/express@4.18.0")
	if err != nil {
		t.Fatal(err)
	}
}

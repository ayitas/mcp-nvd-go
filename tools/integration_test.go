package tools

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ayitas/mcp-nvd-go/nvd"
)

type recordedRequest struct {
	Query    url.Values
	RawQuery string
}

func TestToolsEndToEndScenarios(t *testing.T) {
	t.Parallel()

	var (
		mu       sync.Mutex
		requests []recordedRequest
	)

	mockNVD := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != "NVD-MCP-Server/1.0" {
			http.Error(w, "missing user-agent", http.StatusBadRequest)
			return
		}
		if got := r.Header.Get("apiKey"); got != "integration-key" {
			http.Error(w, "missing api key header", http.StatusBadRequest)
			return
		}
		if got := r.URL.Query().Get("apiKey"); got != "" {
			http.Error(w, "api key must not appear in URL query", http.StatusBadRequest)
			return
		}

		mu.Lock()
		requests = append(requests, recordedRequest{
			Query:    r.URL.Query(),
			RawQuery: r.URL.RawQuery,
		})
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		q := r.URL.Query()

		if q.Get("cveId") != "" && q.Get("resultsPerPage") == "1" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"resultsPerPage": 1,
				"startIndex":     0,
				"totalResults":   1,
				"timestamp":      "2026-05-28T21:00:00.000Z",
				"vulnerabilities": []any{
					map[string]any{
						"cve": map[string]any{
							"id": q.Get("cveId"),
						},
					},
				},
			})
			return
		}

		resultsPerPage, _ := strconv.Atoi(q.Get("resultsPerPage"))
		startIndex, _ := strconv.Atoi(q.Get("startIndex"))
		if resultsPerPage == 0 {
			resultsPerPage = 2000
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"resultsPerPage": resultsPerPage,
			"startIndex":     startIndex,
			"totalResults":   2,
			"timestamp":      "2026-05-28T21:00:00.000Z",
			"vulnerabilities": []any{
				map[string]any{"cve": map[string]any{"id": "CVE-2026-0001"}},
				map[string]any{"cve": map[string]any{"id": "CVE-2026-0002"}},
			},
		})
	}))
	defer mockNVD.Close()

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "nvd-vulnerabilities-test",
		Version: "1.0.0",
	}, nil)
	Register(server, nvd.NewClient("integration-key", mockNVD.URL))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Run(ctx, serverTransport)
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "integration-client", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	defer session.Close()

	t.Run("get_cve_by_id success", func(t *testing.T) {
		result := callTool(t, session, "get_cve_by_id", map[string]any{
			"cve_id": "CVE-2026-12345",
		})
		if result.IsError {
			t.Fatalf("expected non-error result, got error content: %s", resultText(result))
		}

		var out CVEByIDOutput
		mustDecodeStructuredContent(t, result.StructuredContent, &out)
		if out.TotalResults != 1 {
			t.Fatalf("expected totalResults=1, got %d", out.TotalResults)
		}
		if len(out.CVE) == 0 {
			t.Fatalf("expected CVE payload")
		}
	})

	t.Run("search_cves_by_keyword success", func(t *testing.T) {
		result := callTool(t, session, "search_cves_by_keyword", map[string]any{
			"keyword":          "log4j",
			"exact_match":      true,
			"results_per_page": 10,
			"start_index":      5,
		})
		if result.IsError {
			t.Fatalf("expected non-error result, got error content: %s", resultText(result))
		}

		var out CVEListOutput
		mustDecodeStructuredContent(t, result.StructuredContent, &out)
		if out.TotalResults != 2 {
			t.Fatalf("expected totalResults=2, got %d", out.TotalResults)
		}
	})

	t.Run("get_cves_by_cpe success", func(t *testing.T) {
		result := callTool(t, session, "get_cves_by_cpe", map[string]any{
			"cpe_name":         "cpe:2.3:o:microsoft:windows_10",
			"is_vulnerable":    true,
			"results_per_page": 25,
			"start_index":      0,
		})
		if result.IsError {
			t.Fatalf("expected non-error result, got error content: %s", resultText(result))
		}
	})

	t.Run("get_cves_by_date_range encodes plus-offset", func(t *testing.T) {
		result := callTool(t, session, "get_cves_by_date_range", map[string]any{
			"date_type":        "published",
			"start_date":       "2026-01-01T00:00:00+07:00",
			"end_date":         "2026-01-10T23:59:59+07:00",
			"results_per_page": 20,
			"start_index":      0,
		})
		if result.IsError {
			t.Fatalf("expected non-error result, got error content: %s", resultText(result))
		}

		last := lastRecordedRequest(t, &mu, &requests)
		if !strings.Contains(last.RawQuery, "%2B07%3A00") {
			t.Fatalf("expected encoded timezone '+' as %%2B in query, got raw query: %s", last.RawQuery)
		}
	})

	t.Run("get_cves_by_severity success", func(t *testing.T) {
		result := callTool(t, session, "get_cves_by_severity", map[string]any{
			"cvss_version":     "v3",
			"severity":         "CRITICAL",
			"results_per_page": 15,
			"start_index":      3,
		})
		if result.IsError {
			t.Fatalf("expected non-error result, got error content: %s", resultText(result))
		}
	})

	t.Run("get_cves_by_date_range lastModified success", func(t *testing.T) {
		result := callTool(t, session, "get_cves_by_date_range", map[string]any{
			"date_type":   "lastModified",
			"start_date":  "2026-01-01T00:00:00Z",
			"end_date":    "2026-01-10T23:59:59Z",
			"start_index": 2,
		})
		if result.IsError {
			t.Fatalf("expected non-error result, got error content: %s", resultText(result))
		}
	})

	t.Run("get_cves_by_date_range millisecond precision success", func(t *testing.T) {
		result := callTool(t, session, "get_cves_by_date_range", map[string]any{
			"date_type":  "published",
			"start_date": "2026-01-01T00:00:00.000",
			"end_date":   "2026-01-10T23:59:59.000+07:00",
		})
		if result.IsError {
			t.Fatalf("expected non-error result, got error content: %s", resultText(result))
		}
	})

	t.Run("get_cves_by_severity v2 and v4 success", func(t *testing.T) {
		resultV2 := callTool(t, session, "get_cves_by_severity", map[string]any{
			"cvss_version": "v2",
			"severity":     "HIGH",
		})
		if resultV2.IsError {
			t.Fatalf("expected non-error v2 result, got error content: %s", resultText(resultV2))
		}

		resultV4 := callTool(t, session, "get_cves_by_severity", map[string]any{
			"cvss_version": "v4",
			"severity":     "CRITICAL",
		})
		if resultV4.IsError {
			t.Fatalf("expected non-error v4 result, got error content: %s", resultText(resultV4))
		}
	})

	t.Run("search_cves success with multifilters", func(t *testing.T) {
		result := callTool(t, session, "search_cves", map[string]any{
			"cpe_name":            "cpe:2.3:a:apache:log4j",
			"keyword_search":      "remote code execution",
			"keyword_exact_match": true,
			"cvss_v3_severity":    "CRITICAL",
			"vuln_statuses":       []string{"Analyzed", "Modified"},
			"has_kev":             true,
			"no_rejected":         true,
			"results_per_page":    30,
			"start_index":         0,
		})
		if result.IsError {
			t.Fatalf("expected non-error result, got error content: %s", resultText(result))
		}
	})

	t.Run("search_cves validation failure", func(t *testing.T) {
		result := callTool(t, session, "search_cves", map[string]any{
			"keyword_search":   "openssl",
			"cvss_v2_severity": "HIGH",
			"cvss_v3_severity": "HIGH",
		})
		if !result.IsError {
			t.Fatalf("expected validation error result")
		}
		if !strings.Contains(resultText(result), "mutually exclusive") {
			t.Fatalf("expected mutual exclusion error, got: %s", resultText(result))
		}
	})

	t.Run("search_cves maps optional filters to query params", func(t *testing.T) {
		result := callTool(t, session, "search_cves", map[string]any{
			"cpe_name":            "cpe:2.3:a:vendor:product",
			"cve_ids":             []string{"CVE-2026-1111", "CVE-2026-2222"},
			"keyword_search":      "memory corruption",
			"keyword_exact_match": false,
			"cve_tag":             "disputed",
			"cvss_v2_severity":    "HIGH",
			"cwe_id":              "CWE-287",
			"vuln_statuses":       []string{"Analyzed", "Modified"},
			"has_kev":             true,
			"has_cert_alerts":     true,
			"has_cert_notes":      true,
			"has_oval":            true,
			"is_vulnerable":       true,
			"source_identifier":   "cve@mitre.org",
			"no_rejected":         true,
			"pub_start_date":      "2026-01-01T00:00:00Z",
			"pub_end_date":        "2026-01-02T00:00:00Z",
			"last_mod_start_date": "2026-02-01T00:00:00Z",
			"last_mod_end_date":   "2026-02-02T00:00:00Z",
			"kev_start_date":      "2026-03-01T00:00:00Z",
			"kev_end_date":        "2026-03-02T00:00:00Z",
			"results_per_page":    7,
			"start_index":         9,
		})
		if result.IsError {
			t.Fatalf("expected non-error result, got error content: %s", resultText(result))
		}

		last := lastRecordedRequest(t, &mu, &requests)
		assertQueryValue(t, last.Query, "cpeName", "cpe:2.3:a:vendor:product")
		assertQueryValue(t, last.Query, "cveId", "CVE-2026-1111,CVE-2026-2222")
		assertQueryValue(t, last.Query, "keywordSearch", "memory corruption")
		assertQueryValue(t, last.Query, "keywordExactMatch", "false")
		assertQueryValue(t, last.Query, "cveTag", "disputed")
		assertQueryValue(t, last.Query, "cvssV2Severity", "HIGH")
		assertQueryValue(t, last.Query, "cweId", "CWE-287")
		assertQueryValue(t, last.Query, "vulnStatus", "Analyzed,Modified")
		assertQueryValue(t, last.Query, "hasKev", "true")
		assertQueryValue(t, last.Query, "hasCertAlerts", "true")
		assertQueryValue(t, last.Query, "hasCertNotes", "true")
		assertQueryValue(t, last.Query, "hasOval", "true")
		assertQueryValue(t, last.Query, "isVulnerable", "true")
		assertQueryValue(t, last.Query, "sourceIdentifier", "cve@mitre.org")
		assertQueryValue(t, last.Query, "noRejected", "true")
		assertQueryValue(t, last.Query, "pubStartDate", "2026-01-01T00:00:00Z")
		assertQueryValue(t, last.Query, "pubEndDate", "2026-01-02T00:00:00Z")
		assertQueryValue(t, last.Query, "lastModStartDate", "2026-02-01T00:00:00Z")
		assertQueryValue(t, last.Query, "lastModEndDate", "2026-02-02T00:00:00Z")
		assertQueryValue(t, last.Query, "kevStartDate", "2026-03-01T00:00:00Z")
		assertQueryValue(t, last.Query, "kevEndDate", "2026-03-02T00:00:00Z")
		assertQueryValue(t, last.Query, "resultsPerPage", "7")
		assertQueryValue(t, last.Query, "startIndex", "9")
	})

	cancel()
	if err := <-serverErr; err != nil && !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("server returned unexpected error: %v", err)
	}
}

func TestToolsValidationAndErrorScenarios(t *testing.T) {
	t.Parallel()

	mockNVD := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		w.Header().Set("Content-Type", "application/json")

		if q.Get("cveId") == "CVE-2099-0001" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"resultsPerPage":  1,
				"startIndex":      0,
				"totalResults":    0,
				"timestamp":       "2026-05-28T21:00:00.000Z",
				"vulnerabilities": []any{},
			})
			return
		}
		if q.Get("cveId") == "CVE-2099-0002" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"resultsPerPage": 1,
				"startIndex":     0,
				"totalResults":   1,
				"timestamp":      "2026-05-28T21:00:00.000Z",
				"vulnerabilities": []any{
					"not-an-object",
				},
			})
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"resultsPerPage": 1,
			"startIndex":     0,
			"totalResults":   1,
			"timestamp":      "2026-05-28T21:00:00.000Z",
			"vulnerabilities": []any{
				map[string]any{"cve": map[string]any{"id": "CVE-2026-0001"}},
			},
		})
	}))
	defer mockNVD.Close()

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "nvd-vulnerabilities-test-validation",
		Version: "1.0.0",
	}, nil)
	Register(server, nvd.NewClient("integration-key", mockNVD.URL))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Run(ctx, serverTransport)
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "integration-client-validation", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	defer session.Close()

	t.Run("search_cves requires at least one filter", func(t *testing.T) {
		assertToolErrorContains(t, callTool(t, session, "search_cves", map[string]any{}), "at least one filter")
	})

	t.Run("search_cves cve_ids over 100 rejected", func(t *testing.T) {
		cveIDs := make([]string, 101)
		for i := range cveIDs {
			cveIDs[i] = "CVE-2026-12345"
		}
		assertToolErrorContains(t, callTool(t, session, "search_cves", map[string]any{
			"cve_ids": cveIDs,
		}), "at most 100")
	})

	t.Run("search_cves invalid cve id rejected", func(t *testing.T) {
		assertToolErrorContains(t, callTool(t, session, "search_cves", map[string]any{
			"cve_ids": []string{"BAD-123"},
		}), "invalid cve_id")
	})

	t.Run("search_cves keyword exact requires keyword", func(t *testing.T) {
		assertToolErrorContains(t, callTool(t, session, "search_cves", map[string]any{
			"keyword_exact_match": true,
		}), "requires keyword_search")
	})

	t.Run("search_cves is_vulnerable requires cpe_name", func(t *testing.T) {
		assertToolErrorContains(t, callTool(t, session, "search_cves", map[string]any{
			"is_vulnerable": true,
		}), "requires cpe_name")
	})

	t.Run("search_cves invalid severity values rejected", func(t *testing.T) {
		assertToolErrorContains(t, callTool(t, session, "search_cves", map[string]any{
			"cvss_v2_severity": "CRITICAL",
		}), "cvss_v2_severity must")
		assertToolErrorContains(t, callTool(t, session, "search_cves", map[string]any{
			"cvss_v3_severity": "UNKNOWN",
		}), "cvss_v3_severity must")
		assertToolErrorContains(t, callTool(t, session, "search_cves", map[string]any{
			"cvss_v4_severity": "UNKNOWN",
		}), "cvss_v4_severity must")
	})

	t.Run("search_cves vuln_statuses must not include empty", func(t *testing.T) {
		assertToolErrorContains(t, callTool(t, session, "search_cves", map[string]any{
			"vuln_statuses": []string{"Analyzed", ""},
		}), "must not contain empty")
	})

	t.Run("search_cves paired date constraints", func(t *testing.T) {
		assertToolErrorContains(t, callTool(t, session, "search_cves", map[string]any{
			"pub_start_date": "2026-01-01T00:00:00Z",
		}), "must both be provided together")

		assertToolErrorContains(t, callTool(t, session, "search_cves", map[string]any{
			"pub_start_date": "bad-date",
			"pub_end_date":   "2026-01-10T00:00:00Z",
		}), "ISO 8601")

		assertToolErrorContains(t, callTool(t, session, "search_cves", map[string]any{
			"last_mod_start_date": "2026-01-10T00:00:00Z",
			"last_mod_end_date":   "2026-01-01T00:00:00Z",
		}), "greater than or equal")
	})

	t.Run("search_cves pagination bounds", func(t *testing.T) {
		assertToolErrorContains(t, callTool(t, session, "search_cves", map[string]any{
			"keyword_search":   "openssl",
			"results_per_page": 0,
		}), "between 1 and 2000")

		assertToolErrorContains(t, callTool(t, session, "search_cves", map[string]any{
			"keyword_search":   "openssl",
			"results_per_page": 2001,
		}), "between 1 and 2000")

		assertToolErrorContains(t, callTool(t, session, "search_cves", map[string]any{
			"keyword_search": "openssl",
			"start_index":    -1,
		}), "start_index must be >= 0")
	})

	t.Run("get_cve_by_id invalid format", func(t *testing.T) {
		assertToolErrorContains(t, callTool(t, session, "get_cve_by_id", map[string]any{
			"cve_id": "BAD-1",
		}), "must match CVE-YYYY-NNNN")
	})

	t.Run("get_cve_by_id not found", func(t *testing.T) {
		assertToolErrorContains(t, callTool(t, session, "get_cve_by_id", map[string]any{
			"cve_id": "CVE-2099-0001",
		}), "not found")
	})

	t.Run("get_cve_by_id malformed payload", func(t *testing.T) {
		assertToolErrorContains(t, callTool(t, session, "get_cve_by_id", map[string]any{
			"cve_id": "CVE-2099-0002",
		}), "failed to decode cve payload")
	})

	t.Run("get_cves_by_cpe validation", func(t *testing.T) {
		assertToolErrorContains(t, callTool(t, session, "get_cves_by_cpe", map[string]any{
			"cpe_name": "",
		}), "cpe_name is required")

		assertToolErrorContains(t, callTool(t, session, "get_cves_by_cpe", map[string]any{
			"cpe_name":         "cpe:2.3:a:test:app",
			"results_per_page": 2001,
		}), "between 1 and 2000")
	})

	t.Run("search_cves_by_keyword validation", func(t *testing.T) {
		assertToolErrorContains(t, callTool(t, session, "search_cves_by_keyword", map[string]any{
			"keyword": "",
		}), "keyword is required")

		assertToolErrorContains(t, callTool(t, session, "search_cves_by_keyword", map[string]any{
			"keyword":     "openssl",
			"start_index": -1,
		}), "start_index must be >= 0")
	})

	t.Run("get_cves_by_date_range validation", func(t *testing.T) {
		assertToolErrorContains(t, callTool(t, session, "get_cves_by_date_range", map[string]any{
			"date_type":  "invalid",
			"start_date": "2026-01-01T00:00:00Z",
			"end_date":   "2026-01-02T00:00:00Z",
		}), `date_type must be "published" or "lastModified"`)

		assertToolErrorContains(t, callTool(t, session, "get_cves_by_date_range", map[string]any{
			"date_type":  "published",
			"start_date": "bad",
			"end_date":   "2026-01-02T00:00:00Z",
		}), "ISO 8601")

		assertToolErrorContains(t, callTool(t, session, "get_cves_by_date_range", map[string]any{
			"date_type":  "published",
			"start_date": "2026-01-01T00:00:00Z",
			"end_date":   "bad",
		}), "ISO 8601")

		assertToolErrorContains(t, callTool(t, session, "get_cves_by_date_range", map[string]any{
			"date_type":  "published",
			"start_date": "2026-01-03T00:00:00Z",
			"end_date":   "2026-01-02T00:00:00Z",
		}), "greater than or equal")
	})

	t.Run("get_cves_by_severity validation", func(t *testing.T) {
		assertToolErrorContains(t, callTool(t, session, "get_cves_by_severity", map[string]any{
			"cvss_version": "v3",
			"severity":     "",
		}), "severity is required")

		assertToolErrorContains(t, callTool(t, session, "get_cves_by_severity", map[string]any{
			"cvss_version": "vx",
			"severity":     "HIGH",
		}), `cvss_version must be "v2", "v3", or "v4"`)

		assertToolErrorContains(t, callTool(t, session, "get_cves_by_severity", map[string]any{
			"cvss_version": "v2",
			"severity":     "CRITICAL",
		}), "for v2")

		assertToolErrorContains(t, callTool(t, session, "get_cves_by_severity", map[string]any{
			"cvss_version": "v3",
			"severity":     "SEVERE",
		}), "for v3")

		assertToolErrorContains(t, callTool(t, session, "get_cves_by_severity", map[string]any{
			"cvss_version": "v4",
			"severity":     "SEVERE",
		}), "for v4")
	})

	cancel()
	if err := <-serverErr; err != nil && !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("server returned unexpected error: %v", err)
	}
}

func TestToolsBackendErrorPropagation(t *testing.T) {
	t.Parallel()

	mockNVD := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream failure", http.StatusInternalServerError)
	}))
	defer mockNVD.Close()

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "nvd-vulnerabilities-test-backend-error",
		Version: "1.0.0",
	}, nil)
	Register(server, nvd.NewClient("integration-key", mockNVD.URL))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Run(ctx, serverTransport)
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "integration-client-backend-error", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	defer session.Close()

	assertToolErrorContains(t, callTool(t, session, "search_cves", map[string]any{
		"keyword_search": "openssl",
	}), "nvd API returned status 500")
	assertToolErrorContains(t, callTool(t, session, "get_cve_by_id", map[string]any{
		"cve_id": "CVE-2026-12345",
	}), "nvd API returned status 500")
	assertToolErrorContains(t, callTool(t, session, "get_cves_by_cpe", map[string]any{
		"cpe_name": "cpe:2.3:a:test:app",
	}), "nvd API returned status 500")
	assertToolErrorContains(t, callTool(t, session, "search_cves_by_keyword", map[string]any{
		"keyword": "openssl",
	}), "nvd API returned status 500")
	assertToolErrorContains(t, callTool(t, session, "get_cves_by_date_range", map[string]any{
		"date_type":  "published",
		"start_date": "2026-01-01T00:00:00Z",
		"end_date":   "2026-01-02T00:00:00Z",
	}), "nvd API returned status 500")
	assertToolErrorContains(t, callTool(t, session, "get_cves_by_severity", map[string]any{
		"cvss_version": "v3",
		"severity":     "HIGH",
	}), "nvd API returned status 500")

	cancel()
	if err := <-serverErr; err != nil && !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("server returned unexpected error: %v", err)
	}
}

func callTool(t *testing.T, session *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      name,
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("call tool %q failed: %v", name, err)
	}
	return result
}

func mustDecodeStructuredContent(t *testing.T, content any, out any) {
	t.Helper()
	b, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("marshal structured content failed: %v", err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("unmarshal structured content failed: %v", err)
	}
}

func resultText(result *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range result.Content {
		tc, ok := c.(*mcp.TextContent)
		if ok {
			if b.Len() > 0 {
				b.WriteString(" | ")
			}
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func assertToolErrorContains(t *testing.T, result *mcp.CallToolResult, want string) {
	t.Helper()
	if !result.IsError {
		t.Fatalf("expected tool error containing %q, got success", want)
	}
	got := resultText(result)
	if !strings.Contains(got, want) {
		t.Fatalf("expected tool error containing %q, got: %s", want, got)
	}
}

func assertQueryValue(t *testing.T, q url.Values, key, want string) {
	t.Helper()
	if got := q.Get(key); got != want {
		t.Fatalf("query %q = %q, want %q", key, got, want)
	}
}

func lastRecordedRequest(t *testing.T, mu *sync.Mutex, requests *[]recordedRequest) recordedRequest {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	if len(*requests) == 0 {
		t.Fatalf("expected at least one recorded request")
	}
	return (*requests)[len(*requests)-1]
}

package nvd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewClientFromEnvTrimsAPIKey(t *testing.T) {
	t.Setenv("NVD_API_KEY", "  abc123  ")

	client := NewClientFromEnv()
	if client.apiKey != "abc123" {
		t.Fatalf("expected trimmed key, got %q", client.apiKey)
	}
	if client.baseURL != defaultBaseURL {
		t.Fatalf("expected default base url %q, got %q", defaultBaseURL, client.baseURL)
	}
}

func TestSearchCVEsSuccessAndRequestEncoding(t *testing.T) {
	t.Parallel()

	var (
		gotPath      string
		gotRawQuery  string
		gotUserAgent string
		gotAPIKey    string
	)

	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotRawQuery = r.URL.RawQuery
		gotUserAgent = r.Header.Get("User-Agent")
		gotAPIKey = r.Header.Get("apiKey")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"resultsPerPage":1,"startIndex":0,"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-0001"}}]}`))
	}))
	defer mock.Close()

	client := NewClient("  my-key  ", mock.URL+"/cves/2.0")
	resp, err := client.SearchCVEs(context.Background(), map[string]string{
		"pubStartDate": "2026-01-01T00:00:00+07:00",
		"pubEndDate":   "2026-01-02T00:00:00+07:00",
		"empty":        "   ",
	})
	if err != nil {
		t.Fatalf("SearchCVEs returned error: %v", err)
	}
	if resp.TotalResults != 1 {
		t.Fatalf("expected totalResults=1, got %d", resp.TotalResults)
	}
	if gotPath != "/cves/2.0" {
		t.Fatalf("expected path /cves/2.0, got %q", gotPath)
	}
	if gotUserAgent != userAgent {
		t.Fatalf("expected user-agent %q, got %q", userAgent, gotUserAgent)
	}
	if gotAPIKey != "my-key" {
		t.Fatalf("expected api key in header, got %q", gotAPIKey)
	}
	if strings.Contains(gotRawQuery, "apiKey=") {
		t.Fatalf("api key must not appear in URL query, got %q", gotRawQuery)
	}
	if !strings.Contains(gotRawQuery, "%2B07%3A00") {
		t.Fatalf("expected timezone '+' encoded as %%2B, got %q", gotRawQuery)
	}
	if strings.Contains(gotRawQuery, "empty=") {
		t.Fatalf("did not expect empty trimmed params in query: %q", gotRawQuery)
	}
}

func TestSearchCVEsRateLimiterCancelledContext(t *testing.T) {
	t.Parallel()

	client := NewClient("", "https://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.SearchCVEs(ctx, map[string]string{"keywordSearch": "test"})
	if err == nil || !strings.Contains(err.Error(), "rate limiter wait failed") {
		t.Fatalf("expected rate limiter error, got: %v", err)
	}
}

func TestSearchCVEsInvalidBaseURL(t *testing.T) {
	t.Parallel()

	client := NewClient("", "://bad-url")
	_, err := client.SearchCVEs(context.Background(), map[string]string{"keywordSearch": "test"})
	if err == nil || !strings.Contains(err.Error(), "invalid base URL") {
		t.Fatalf("expected invalid base url error, got: %v", err)
	}
}

func TestSearchCVEsHTTPErrorAndDecodeError(t *testing.T) {
	t.Parallel()

	t.Run("non-200 status", func(t *testing.T) {
		mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
		}))
		defer mock.Close()

		client := NewClient("", mock.URL)
		_, err := client.SearchCVEs(context.Background(), map[string]string{"keywordSearch": "test"})
		if err == nil || !strings.Contains(err.Error(), "nvd API returned status 429") {
			t.Fatalf("expected HTTP status error, got: %v", err)
		}
	})

	t.Run("invalid json body", func(t *testing.T) {
		mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{not-json`))
		}))
		defer mock.Close()

		client := NewClient("", mock.URL)
		_, err := client.SearchCVEs(context.Background(), map[string]string{"keywordSearch": "test"})
		if err == nil || !strings.Contains(err.Error(), "failed to decode NVD response") {
			t.Fatalf("expected decode error, got: %v", err)
		}
	})
}

func TestSearchCVEsRequestFailure(t *testing.T) {
	t.Parallel()

	// Parseable URL but non-routable port triggers a transport-level request error.
	client := NewClient("", "http://127.0.0.1:1")
	_, err := client.SearchCVEs(context.Background(), map[string]string{"keywordSearch": "test"})
	if err == nil || !strings.Contains(err.Error(), "request failed") {
		t.Fatalf("expected request failed error, got: %v", err)
	}
}

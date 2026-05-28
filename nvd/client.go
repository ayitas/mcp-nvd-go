// Package nvd is a thin client for the NIST NVD CVE 2.0 API.
//
// The client enforces NVD's documented rate limits (5 requests per rolling
// 30 second window without an API key; 50 per 30 seconds with a key),
// passes the API key in the request header rather than the URL, and bounds
// the response body to prevent runaway memory use.
package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

const (
	defaultBaseURL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	userAgent       = "NVD-MCP-Server/1.0"
	httpTimeout     = 30 * time.Second
	maxResponseSize = 50 << 20 // 50 MiB, ~3x the realistic worst case for resultsPerPage=2000.
)

// NVD documents its limits as "N requests in a rolling 30 second window".
// We model that as a token bucket of N tokens that refills over 30 seconds.
const (
	publicWindowRequests = 5
	keyedWindowRequests  = 50
	windowDuration       = 30 * time.Second
)

// Client talks to the NVD CVE 2.0 API.
//
// Construct it with NewClientFromEnv (production) or NewClient (tests).
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
	limiter    *rate.Limiter
}

// CVEResponse mirrors the envelope returned by the NVD CVE 2.0 API.
// Vulnerabilities are kept as RawMessage so downstream code can choose its
// own decoding strategy without paying for a double unmarshal here.
type CVEResponse struct {
	ResultsPerPage  int               `json:"resultsPerPage"`
	StartIndex      int               `json:"startIndex"`
	TotalResults    int               `json:"totalResults"`
	Format          string            `json:"format,omitempty"`
	Version         string            `json:"version,omitempty"`
	Timestamp       string            `json:"timestamp,omitempty"`
	Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
}

// NewClientFromEnv reads NVD_API_KEY from the environment and returns a
// Client targeting the production NVD endpoint.
func NewClientFromEnv() *Client {
	return NewClient(os.Getenv("NVD_API_KEY"), "")
}

// NewClient builds a Client with the given API key and base URL.
// An empty apiKey selects the public rate-limit class; an empty baseURL
// selects the production NVD endpoint.
func NewClient(apiKey, baseURL string) *Client {
	apiKey = strings.TrimSpace(apiKey)
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	requestsPerWindow := publicWindowRequests
	if apiKey != "" {
		requestsPerWindow = keyedWindowRequests
	}
	limit := rate.Limit(float64(requestsPerWindow) / windowDuration.Seconds())

	return &Client{
		apiKey:     apiKey,
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: httpTimeout},
		limiter:    rate.NewLimiter(limit, requestsPerWindow),
	}
}

// SearchCVEs issues a single GET against the configured NVD endpoint.
// params are merged into the URL query verbatim; empty values are dropped.
// The API key, if any, is sent in the "apiKey" request header (NVD's
// recommended channel) so it does not appear in request URLs.
func (c *Client) SearchCVEs(ctx context.Context, params map[string]string) (*CVEResponse, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter wait failed: %w", err)
	}

	u, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	query := u.Query()
	for k, v := range params {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			query.Set(k, trimmed)
		}
	}
	u.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body := io.LimitReader(resp.Body, maxResponseSize)

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(body, 4096))
		return nil, fmt.Errorf("nvd API returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	var out CVEResponse
	if err := json.NewDecoder(body).Decode(&out); err != nil {
		return nil, fmt.Errorf("failed to decode NVD response: %w", err)
	}
	return &out, nil
}

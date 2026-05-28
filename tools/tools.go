// Package tools registers the MCP tools that wrap the NVD CVE 2.0 API.
//
// Tool inputs are strongly typed; the SDK derives the JSON Schema from the
// struct tags. Every tool is read-only (NVD GET) and interacts with an
// open external world (the NVD service), which is reflected in the
// MCP tool annotations.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ayitas/mcp-nvd-go/nvd"
)

// readOnlyAnnotations is the same annotation set for every tool we expose.
// All tools are read-only NVD queries against an open external world.
func readOnlyAnnotations() *mcp.ToolAnnotations {
	openWorld := true
	return &mcp.ToolAnnotations{
		ReadOnlyHint:  true,
		OpenWorldHint: &openWorld,
	}
}

var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// acceptedDateLayouts lists the ISO 8601 variants accepted by tool date inputs.
// NVD's CVE 2.0 API accepts millisecond-precision timestamps with or without
// timezone offsets; we keep the parser permissive on input while still emitting
// the original string downstream to NVD.
var acceptedDateLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.000Z07:00",
	"2006-01-02T15:04:05.000",
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02T15:04:05",
}

var (
	v2Severities  = []string{"LOW", "MEDIUM", "HIGH"}
	v34Severities = []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"}
)

type CVEListOutput struct {
	TotalResults    int              `json:"totalResults" jsonschema:"Total number of matching CVEs in NVD"`
	ResultsPerPage  int              `json:"resultsPerPage" jsonschema:"Number of CVEs included in this page"`
	StartIndex      int              `json:"startIndex" jsonschema:"Pagination start index used for this result set"`
	Timestamp       string           `json:"timestamp,omitempty" jsonschema:"NVD response timestamp in ISO 8601"`
	Vulnerabilities []map[string]any `json:"vulnerabilities" jsonschema:"Vulnerability objects from NVD CVE API"`
}

type CVEByIDOutput struct {
	TotalResults int            `json:"totalResults" jsonschema:"Total matching CVEs for the requested ID"`
	Timestamp    string         `json:"timestamp,omitempty" jsonschema:"NVD response timestamp in ISO 8601"`
	CVE          map[string]any `json:"cve" jsonschema:"Single CVE vulnerability object"`
}

type SearchCVEsInput struct {
	CPEName          string   `json:"cpe_name,omitempty" jsonschema:"Filter by CPE name (e.g. cpe:2.3:o:microsoft:windows_10)"`
	CVEIDs           []string `json:"cve_ids,omitempty" jsonschema:"List of up to 100 CVE IDs"`
	KeywordSearch    string   `json:"keyword_search,omitempty" jsonschema:"Keywords to search in CVE descriptions"`
	KeywordExact     *bool    `json:"keyword_exact_match,omitempty" jsonschema:"Exact phrase match toggle, requires keyword_search"`
	CVETag           string   `json:"cve_tag,omitempty" jsonschema:"Filter by CVE tag such as disputed"`
	CVSSV2Severity   string   `json:"cvss_v2_severity,omitempty" jsonschema:"CVSS v2 severity (LOW, MEDIUM, HIGH)"`
	CVSSV3Severity   string   `json:"cvss_v3_severity,omitempty" jsonschema:"CVSS v3 severity (LOW, MEDIUM, HIGH, CRITICAL)"`
	CVSSV4Severity   string   `json:"cvss_v4_severity,omitempty" jsonschema:"CVSS v4 severity (LOW, MEDIUM, HIGH, CRITICAL)"`
	CWEID            string   `json:"cwe_id,omitempty" jsonschema:"Filter by CWE ID (e.g. CWE-287)"`
	VulnStatuses     []string `json:"vuln_statuses,omitempty" jsonschema:"List of vulnerability statuses such as Analyzed or Modified"`
	HasKEV           *bool    `json:"has_kev,omitempty" jsonschema:"Only CVEs in CISA Known Exploited Vulnerabilities catalog"`
	HasCertAlerts    *bool    `json:"has_cert_alerts,omitempty" jsonschema:"Only CVEs with US-CERT technical alerts"`
	HasCertNotes     *bool    `json:"has_cert_notes,omitempty" jsonschema:"Only CVEs with CERT/CC vulnerability notes"`
	HasOVAL          *bool    `json:"has_oval,omitempty" jsonschema:"Only CVEs with OVAL records"`
	IsVulnerable     *bool    `json:"is_vulnerable,omitempty" jsonschema:"When true, only CVEs where cpe_name is marked vulnerable"`
	SourceIdentifier string   `json:"source_identifier,omitempty" jsonschema:"Filter by source identifier such as cve@mitre.org"`
	NoRejected       *bool    `json:"no_rejected,omitempty" jsonschema:"Exclude rejected CVEs"`
	PubStartDate     string   `json:"pub_start_date,omitempty" jsonschema:"Published date range start in ISO 8601"`
	PubEndDate       string   `json:"pub_end_date,omitempty" jsonschema:"Published date range end in ISO 8601"`
	LastModStartDate string   `json:"last_mod_start_date,omitempty" jsonschema:"Last modified date range start in ISO 8601"`
	LastModEndDate   string   `json:"last_mod_end_date,omitempty" jsonschema:"Last modified date range end in ISO 8601"`
	KEVStartDate     string   `json:"kev_start_date,omitempty" jsonschema:"KEV added date range start in ISO 8601"`
	KEVEndDate       string   `json:"kev_end_date,omitempty" jsonschema:"KEV added date range end in ISO 8601"`
	ResultsPerPage   *int     `json:"results_per_page,omitempty" jsonschema:"Page size, default 2000, maximum 2000"`
	StartIndex       *int     `json:"start_index,omitempty" jsonschema:"Zero-based pagination start index"`
}

type GetCVEByIDInput struct {
	CVEID string `json:"cve_id" jsonschema:"Exact CVE ID, for example CVE-2023-12345"`
}

type GetCVEsByCPEInput struct {
	CPEName        string `json:"cpe_name" jsonschema:"Full or partial CPE name"`
	IsVulnerable   *bool  `json:"is_vulnerable,omitempty" jsonschema:"Only return CVEs where CPE is explicitly marked vulnerable"`
	ResultsPerPage *int   `json:"results_per_page,omitempty" jsonschema:"Page size, default 2000, maximum 2000"`
	StartIndex     *int   `json:"start_index,omitempty" jsonschema:"Zero-based pagination start index"`
}

type SearchCVEsByKeywordInput struct {
	Keyword        string `json:"keyword" jsonschema:"Keyword or phrase to search in CVE descriptions"`
	ExactMatch     *bool  `json:"exact_match,omitempty" jsonschema:"Set true for exact phrase search"`
	ResultsPerPage *int   `json:"results_per_page,omitempty" jsonschema:"Page size, default 2000, maximum 2000"`
	StartIndex     *int   `json:"start_index,omitempty" jsonschema:"Zero-based pagination start index"`
}

type GetCVEsByDateRangeInput struct {
	DateType       string `json:"date_type" jsonschema:"Date selector: published or lastModified"`
	StartDate      string `json:"start_date" jsonschema:"Range start in ISO 8601"`
	EndDate        string `json:"end_date" jsonschema:"Range end in ISO 8601"`
	ResultsPerPage *int   `json:"results_per_page,omitempty" jsonschema:"Page size, default 2000, maximum 2000"`
	StartIndex     *int   `json:"start_index,omitempty" jsonschema:"Zero-based pagination start index"`
}

type GetCVEsBySeverityInput struct {
	CVSSVersion    string `json:"cvss_version" jsonschema:"CVSS version selector: v2, v3, or v4"`
	Severity       string `json:"severity" jsonschema:"Qualitative severity level"`
	ResultsPerPage *int   `json:"results_per_page,omitempty" jsonschema:"Page size, default 2000, maximum 2000"`
	StartIndex     *int   `json:"start_index,omitempty" jsonschema:"Zero-based pagination start index"`
}

func Register(server *mcp.Server, client *nvd.Client) {
	registerSearchCVEs(server, client)
	registerGetCVEByID(server, client)
	registerGetCVEsByCPE(server, client)
	registerSearchCVEsByKeyword(server, client)
	registerGetCVEsByDateRange(server, client)
	registerGetCVEsBySeverity(server, client)
}

func registerSearchCVEs(server *mcp.Server, client *nvd.Client) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "search_cves",
		Description: "Primary tool for multi-faceted CVE searches against the NVD. " +
			"Combine any subset of filters: CPE name, CVE IDs, keyword, CVSS v2/v3/v4 severity, CWE, " +
			"vulnerability status, KEV/CERT/OVAL presence, source, and pub/lastMod/KEV date ranges. " +
			"Use the narrower tools (get_cve_by_id, get_cves_by_cpe, search_cves_by_keyword, " +
			"get_cves_by_date_range, get_cves_by_severity) when only one of these filters applies.",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in SearchCVEsInput) (*mcp.CallToolResult, CVEListOutput, error) {
		if err := validateSearchCVEsInput(in); err != nil {
			return nil, CVEListOutput{}, err
		}
		resultsPerPage, startIndex, err := validatePagination(in.ResultsPerPage, in.StartIndex)
		if err != nil {
			return nil, CVEListOutput{}, err
		}

		params := paginationParams(resultsPerPage, startIndex)
		setIfNonEmpty(params, "cpeName", in.CPEName)
		if len(in.CVEIDs) > 0 {
			params["cveId"] = strings.Join(in.CVEIDs, ",")
		}
		setIfNonEmpty(params, "keywordSearch", in.KeywordSearch)
		setBoolPtr(params, "keywordExactMatch", in.KeywordExact)
		setIfNonEmpty(params, "cveTag", in.CVETag)
		setIfNonEmpty(params, "cvssV2Severity", strings.ToUpper(in.CVSSV2Severity))
		setIfNonEmpty(params, "cvssV3Severity", strings.ToUpper(in.CVSSV3Severity))
		setIfNonEmpty(params, "cvssV4Severity", strings.ToUpper(in.CVSSV4Severity))
		setIfNonEmpty(params, "cweId", in.CWEID)
		if len(in.VulnStatuses) > 0 {
			params["vulnStatus"] = strings.Join(in.VulnStatuses, ",")
		}
		setBoolPtr(params, "hasKev", in.HasKEV)
		setBoolPtr(params, "hasCertAlerts", in.HasCertAlerts)
		setBoolPtr(params, "hasCertNotes", in.HasCertNotes)
		setBoolPtr(params, "hasOval", in.HasOVAL)
		setBoolPtr(params, "isVulnerable", in.IsVulnerable)
		setIfNonEmpty(params, "sourceIdentifier", in.SourceIdentifier)
		setBoolPtr(params, "noRejected", in.NoRejected)
		setPairedDates(params, "pubStartDate", "pubEndDate", in.PubStartDate, in.PubEndDate)
		setPairedDates(params, "lastModStartDate", "lastModEndDate", in.LastModStartDate, in.LastModEndDate)
		setPairedDates(params, "kevStartDate", "kevEndDate", in.KEVStartDate, in.KEVEndDate)

		resp, err := client.SearchCVEs(ctx, params)
		if err != nil {
			return nil, CVEListOutput{}, err
		}
		return nil, toListOutput(resp), nil
	})
}

func registerGetCVEByID(server *mcp.Server, client *nvd.Client) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "get_cve_by_id",
		Description: "Fetch the full NVD record for a single CVE by its exact ID " +
			"(e.g. CVE-2023-12345). Use search_cves with cve_ids when you need many.",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in GetCVEByIDInput) (*mcp.CallToolResult, CVEByIDOutput, error) {
		cveID := normalizeCVEID(in.CVEID)
		if !cveIDPattern.MatchString(cveID) {
			return nil, CVEByIDOutput{}, fmt.Errorf("cve_id must match CVE-YYYY-NNNN format")
		}

		resp, err := client.SearchCVEs(ctx, map[string]string{
			"cveId":          cveID,
			"resultsPerPage": "1",
			"startIndex":     "0",
		})
		if err != nil {
			return nil, CVEByIDOutput{}, err
		}
		if resp.TotalResults == 0 || len(resp.Vulnerabilities) == 0 {
			return nil, CVEByIDOutput{}, fmt.Errorf("CVE ID not found: %s", cveID)
		}
		var cve map[string]any
		if err := json.Unmarshal(resp.Vulnerabilities[0], &cve); err != nil {
			return nil, CVEByIDOutput{}, fmt.Errorf("failed to decode cve payload: %w", err)
		}

		return nil, CVEByIDOutput{
			TotalResults: resp.TotalResults,
			Timestamp:    resp.Timestamp,
			CVE:          cve,
		}, nil
	})
}

func registerGetCVEsByCPE(server *mcp.Server, client *nvd.Client) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "get_cves_by_cpe",
		Description: "List CVEs that match a CPE 2.3 name (full or partial). " +
			"Set is_vulnerable=true to keep only CVEs where the CPE is explicitly marked vulnerable.",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in GetCVEsByCPEInput) (*mcp.CallToolResult, CVEListOutput, error) {
		if strings.TrimSpace(in.CPEName) == "" {
			return nil, CVEListOutput{}, fmt.Errorf("cpe_name is required")
		}
		resultsPerPage, startIndex, err := validatePagination(in.ResultsPerPage, in.StartIndex)
		if err != nil {
			return nil, CVEListOutput{}, err
		}

		params := paginationParams(resultsPerPage, startIndex)
		params["cpeName"] = strings.TrimSpace(in.CPEName)
		setBoolPtr(params, "isVulnerable", in.IsVulnerable)

		resp, err := client.SearchCVEs(ctx, params)
		if err != nil {
			return nil, CVEListOutput{}, err
		}
		return nil, toListOutput(resp), nil
	})
}

func registerSearchCVEsByKeyword(server *mcp.Server, client *nvd.Client) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "search_cves_by_keyword",
		Description: "Free-text search across CVE descriptions. Set exact_match=true to " +
			"require the phrase verbatim. For combined filters use search_cves.",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in SearchCVEsByKeywordInput) (*mcp.CallToolResult, CVEListOutput, error) {
		if strings.TrimSpace(in.Keyword) == "" {
			return nil, CVEListOutput{}, fmt.Errorf("keyword is required")
		}
		resultsPerPage, startIndex, err := validatePagination(in.ResultsPerPage, in.StartIndex)
		if err != nil {
			return nil, CVEListOutput{}, err
		}

		params := paginationParams(resultsPerPage, startIndex)
		params["keywordSearch"] = strings.TrimSpace(in.Keyword)
		setBoolPtr(params, "keywordExactMatch", in.ExactMatch)

		resp, err := client.SearchCVEs(ctx, params)
		if err != nil {
			return nil, CVEListOutput{}, err
		}
		return nil, toListOutput(resp), nil
	})
}

func registerGetCVEsByDateRange(server *mcp.Server, client *nvd.Client) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "get_cves_by_date_range",
		Description: "List CVEs published or last-modified between two ISO 8601 timestamps. " +
			"date_type selects which timestamp (\"published\" or \"lastModified\"). " +
			"NVD caps a single range at 120 days; the server itself does not split, so callers should chunk longer windows.",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in GetCVEsByDateRangeInput) (*mcp.CallToolResult, CVEListOutput, error) {
		dateType := strings.TrimSpace(in.DateType)
		switch dateType {
		case "published", "lastModified":
		default:
			return nil, CVEListOutput{}, fmt.Errorf(`date_type must be "published" or "lastModified"`)
		}
		if err := validateDateRange(in.StartDate, in.EndDate, "start_date", "end_date"); err != nil {
			return nil, CVEListOutput{}, err
		}
		resultsPerPage, startIndex, err := validatePagination(in.ResultsPerPage, in.StartIndex)
		if err != nil {
			return nil, CVEListOutput{}, err
		}

		params := paginationParams(resultsPerPage, startIndex)
		if dateType == "published" {
			params["pubStartDate"] = in.StartDate
			params["pubEndDate"] = in.EndDate
		} else {
			params["lastModStartDate"] = in.StartDate
			params["lastModEndDate"] = in.EndDate
		}

		resp, err := client.SearchCVEs(ctx, params)
		if err != nil {
			return nil, CVEListOutput{}, err
		}
		return nil, toListOutput(resp), nil
	})
}

func registerGetCVEsBySeverity(server *mcp.Server, client *nvd.Client) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "get_cves_by_severity",
		Description: "List CVEs at a given CVSS qualitative severity. " +
			"cvss_version is \"v2\" (LOW/MEDIUM/HIGH), \"v3\" or \"v4\" (LOW/MEDIUM/HIGH/CRITICAL).",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in GetCVEsBySeverityInput) (*mcp.CallToolResult, CVEListOutput, error) {
		version := strings.ToLower(strings.TrimSpace(in.CVSSVersion))
		severity := strings.ToUpper(strings.TrimSpace(in.Severity))
		if severity == "" {
			return nil, CVEListOutput{}, fmt.Errorf("severity is required")
		}
		paramKey, err := validateSeverityForVersion(version, severity)
		if err != nil {
			return nil, CVEListOutput{}, err
		}
		resultsPerPage, startIndex, err := validatePagination(in.ResultsPerPage, in.StartIndex)
		if err != nil {
			return nil, CVEListOutput{}, err
		}

		params := paginationParams(resultsPerPage, startIndex)
		params[paramKey] = severity

		resp, err := client.SearchCVEs(ctx, params)
		if err != nil {
			return nil, CVEListOutput{}, err
		}
		return nil, toListOutput(resp), nil
	})
}

func validateSearchCVEsInput(in SearchCVEsInput) error {
	if !hasAtLeastOneSearchFilter(in) {
		return fmt.Errorf("at least one filter parameter must be provided")
	}

	if len(in.CVEIDs) > 100 {
		return fmt.Errorf("cve_ids accepts at most 100 items")
	}
	for _, id := range in.CVEIDs {
		if !cveIDPattern.MatchString(normalizeCVEID(id)) {
			return fmt.Errorf("invalid cve_id in cve_ids: %q", id)
		}
	}

	if in.KeywordExact != nil && strings.TrimSpace(in.KeywordSearch) == "" {
		return fmt.Errorf("keyword_exact_match requires keyword_search")
	}

	if in.IsVulnerable != nil && strings.TrimSpace(in.CPEName) == "" {
		return fmt.Errorf("is_vulnerable requires cpe_name")
	}

	severityFields := 0
	if strings.TrimSpace(in.CVSSV2Severity) != "" {
		severityFields++
		if !isInSet(strings.ToUpper(in.CVSSV2Severity), v2Severities...) {
			return fmt.Errorf("cvss_v2_severity must be LOW, MEDIUM, or HIGH")
		}
	}
	if strings.TrimSpace(in.CVSSV3Severity) != "" {
		severityFields++
		if !isInSet(strings.ToUpper(in.CVSSV3Severity), v34Severities...) {
			return fmt.Errorf("cvss_v3_severity must be LOW, MEDIUM, HIGH, or CRITICAL")
		}
	}
	if strings.TrimSpace(in.CVSSV4Severity) != "" {
		severityFields++
		if !isInSet(strings.ToUpper(in.CVSSV4Severity), v34Severities...) {
			return fmt.Errorf("cvss_v4_severity must be LOW, MEDIUM, HIGH, or CRITICAL")
		}
	}
	if severityFields > 1 {
		return fmt.Errorf("cvss_v2_severity, cvss_v3_severity, and cvss_v4_severity are mutually exclusive")
	}

	for _, status := range in.VulnStatuses {
		if strings.TrimSpace(status) == "" {
			return fmt.Errorf("vuln_statuses must not contain empty values")
		}
	}

	if err := validatePairedDateRange(in.PubStartDate, in.PubEndDate, "pub_start_date", "pub_end_date"); err != nil {
		return err
	}
	if err := validatePairedDateRange(in.LastModStartDate, in.LastModEndDate, "last_mod_start_date", "last_mod_end_date"); err != nil {
		return err
	}
	if err := validatePairedDateRange(in.KEVStartDate, in.KEVEndDate, "kev_start_date", "kev_end_date"); err != nil {
		return err
	}
	return nil
}

// validateSeverityForVersion validates severity against the given CVSS version
// and returns the NVD query parameter name that should carry the value.
func validateSeverityForVersion(version, severity string) (string, error) {
	switch version {
	case "v2":
		if !isInSet(severity, v2Severities...) {
			return "", fmt.Errorf("severity must be one of LOW, MEDIUM, HIGH for v2")
		}
		return "cvssV2Severity", nil
	case "v3":
		if !isInSet(severity, v34Severities...) {
			return "", fmt.Errorf("severity must be one of LOW, MEDIUM, HIGH, CRITICAL for v3")
		}
		return "cvssV3Severity", nil
	case "v4":
		if !isInSet(severity, v34Severities...) {
			return "", fmt.Errorf("severity must be one of LOW, MEDIUM, HIGH, CRITICAL for v4")
		}
		return "cvssV4Severity", nil
	default:
		return "", fmt.Errorf(`cvss_version must be "v2", "v3", or "v4"`)
	}
}

func hasAtLeastOneSearchFilter(in SearchCVEsInput) bool {
	return strings.TrimSpace(in.CPEName) != "" ||
		len(in.CVEIDs) > 0 ||
		strings.TrimSpace(in.KeywordSearch) != "" ||
		in.KeywordExact != nil ||
		strings.TrimSpace(in.CVETag) != "" ||
		strings.TrimSpace(in.CVSSV2Severity) != "" ||
		strings.TrimSpace(in.CVSSV3Severity) != "" ||
		strings.TrimSpace(in.CVSSV4Severity) != "" ||
		strings.TrimSpace(in.CWEID) != "" ||
		len(in.VulnStatuses) > 0 ||
		in.HasKEV != nil ||
		in.HasCertAlerts != nil ||
		in.HasCertNotes != nil ||
		in.HasOVAL != nil ||
		in.IsVulnerable != nil ||
		strings.TrimSpace(in.SourceIdentifier) != "" ||
		in.NoRejected != nil ||
		strings.TrimSpace(in.PubStartDate) != "" ||
		strings.TrimSpace(in.PubEndDate) != "" ||
		strings.TrimSpace(in.LastModStartDate) != "" ||
		strings.TrimSpace(in.LastModEndDate) != "" ||
		strings.TrimSpace(in.KEVStartDate) != "" ||
		strings.TrimSpace(in.KEVEndDate) != ""
}

func validatePagination(resultsPerPage *int, startIndex *int) (int, int, error) {
	rpp := 2000
	if resultsPerPage != nil {
		rpp = *resultsPerPage
	}
	if rpp < 1 || rpp > 2000 {
		return 0, 0, fmt.Errorf("results_per_page must be between 1 and 2000")
	}

	si := 0
	if startIndex != nil {
		si = *startIndex
	}
	if si < 0 {
		return 0, 0, fmt.Errorf("start_index must be >= 0")
	}

	return rpp, si, nil
}

func validatePairedDateRange(start, end, startName, endName string) error {
	start = strings.TrimSpace(start)
	end = strings.TrimSpace(end)
	if start == "" && end == "" {
		return nil
	}
	if start == "" || end == "" {
		return fmt.Errorf("%s and %s must both be provided together", startName, endName)
	}
	return validateDateRange(start, end, startName, endName)
}

func validateDateRange(start, end, startName, endName string) error {
	startT, err := parseISO8601(start)
	if err != nil {
		return fmt.Errorf("%s must be ISO 8601: %w", startName, err)
	}
	endT, err := parseISO8601(end)
	if err != nil {
		return fmt.Errorf("%s must be ISO 8601: %w", endName, err)
	}
	if endT.Before(startT) {
		return fmt.Errorf("%s must be greater than or equal to %s", endName, startName)
	}
	return nil
}

// parseISO8601 parses common ISO 8601 timestamp variants accepted by the NVD
// API, including RFC3339, RFC3339Nano, and millisecond-precision variants with
// or without timezone offsets.
func parseISO8601(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	for _, layout := range acceptedDateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized timestamp %q", s)
}

func isInSet(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func normalizeCVEID(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
}

func paginationParams(resultsPerPage, startIndex int) map[string]string {
	return map[string]string{
		"resultsPerPage": strconv.Itoa(resultsPerPage),
		"startIndex":     strconv.Itoa(startIndex),
	}
}

func setIfNonEmpty(params map[string]string, key, value string) {
	if strings.TrimSpace(value) != "" {
		params[key] = value
	}
}

func setBoolPtr(params map[string]string, key string, value *bool) {
	if value != nil {
		params[key] = strconv.FormatBool(*value)
	}
}

func setPairedDates(params map[string]string, startKey, endKey, start, end string) {
	if strings.TrimSpace(start) == "" || strings.TrimSpace(end) == "" {
		return
	}
	params[startKey] = start
	params[endKey] = end
}

func toListOutput(resp *nvd.CVEResponse) CVEListOutput {
	vulnerabilities := make([]map[string]any, 0, len(resp.Vulnerabilities))
	for _, vuln := range resp.Vulnerabilities {
		var decoded map[string]any
		if err := json.Unmarshal(vuln, &decoded); err == nil {
			vulnerabilities = append(vulnerabilities, decoded)
		}
	}

	return CVEListOutput{
		TotalResults:    resp.TotalResults,
		ResultsPerPage:  resp.ResultsPerPage,
		StartIndex:      resp.StartIndex,
		Timestamp:       resp.Timestamp,
		Vulnerabilities: vulnerabilities,
	}
}

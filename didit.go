// Package didit_api_v3 is a self-contained, standard-library-only client for
// the Didit V3 identity verification and management API.
//
// It covers the full lifecycle:
//
//	Sessions  — create, retrieve, list, update status, delete, generate PDF,
//	            share a session (reusable KYC) with a partner application.
//	Workflows — list, get, create, update, delete.
//	Users     — list, get, create, update, change status, batch delete,
//	            generate a user-history PDF.
//	Lists     — list, get, create, rename, delete; add, list, and remove
//	            entries (blocklists, allowlists, custom lists).
//
// All HTTP plumbing, HMAC verification, and JSON decoding are private.
// Callers deal only with typed structs and named methods.
package didit_api_v3

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// ── Configuration ──────────────────────────────────────────────────────────

// Config is fed to Init from your main package.
type Config struct {
	APIKey        string // Didit Console → Settings → API & Webhooks
	WorkflowID    string // default workflow UUID; individual calls may override
	WebhookSecret string // used to verify inbound webhook signatures
	BaseURL       string // optional; defaults to https://verification.didit.me/v3
	HTTPClient    *http.Client
}

// Client is the initialized Didit client. Safe for concurrent use.
type Client struct {
	cfg  Config
	http *http.Client
}

// Init validates the configuration and returns a ready client.
func Init(cfg Config) (*Client, error) {
	if cfg.APIKey == "" {
		return nil, errors.New("didit: APIKey is required")
	}
	if cfg.WebhookSecret == "" {
		return nil, errors.New("didit: WebhookSecret is required for signature verification")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://verification.didit.me/v3"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{cfg: cfg, http: cfg.HTTPClient}, nil
}

// WorkflowID returns the default workflow UUID configured at Init.
func (c *Client) WorkflowID() string { return c.cfg.WorkflowID }

// ── Private HTTP helpers ───────────────────────────────────────────────────

// doJSON performs an HTTP request with a JSON body and decodes the JSON
// response into out. If out is nil, the response body is discarded.
func (c *Client) doJSON(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("didit: marshal request: %w", err)
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.cfg.BaseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("x-api-key", c.cfg.APIKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("didit: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{
			StatusCode: resp.StatusCode,
			Path:       path,
			Body:       string(raw),
		}
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("didit: decode %s %s: %w", method, path, err)
	}
	return nil
}

// doRaw performs an HTTP request and returns the raw response body. Used for
// binary endpoints (PDF generation).
func (c *Client) doRaw(ctx context.Context, method, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-api-key", c.cfg.APIKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("didit: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Path:       path,
			Body:       string(raw),
		}
	}
	return raw, nil
}

// APIError is returned for any non-2xx response. It carries the status code,
// the request path, and the raw response body so callers can log or branch.
type APIError struct {
	StatusCode int
	Path       string
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("didit: %s -> %d: %s", e.Path, e.StatusCode, e.Body)
}

// buildQuery renders a url.Values into a query string, omitting empty values.
func buildQuery(v url.Values) string {
	if len(v) == 0 {
		return ""
	}
	return "?" + v.Encode()
}

// ── Session types ──────────────────────────────────────────────────────────

// CreateSessionRequest is the body sent to POST /session/.
type CreateSessionRequest struct {
	WorkflowID string `json:"workflow_id,omitempty"`
	// VendorData is your internal identifier (user ID, email, etc.).
	// It is echoed back in every webhook so you can correlate the result.
	VendorData string `json:"vendor_data,omitempty"`
	// Callback is where the user is sent AFTER they finish the flow in the
	// browser. This is NOT the webhook URL; it is the browser redirect.
	Callback string `json:"callback,omitempty"`
	// CallbackMethod controls which device handles the redirect.
	// One of "initiator", "completer", "both". Default: "initiator".
	CallbackMethod string `json:"callback_method,omitempty"`
	// Language forces the UI language (e.g. "fr", "en"). Omit for auto-detect.
	Language string `json:"language,omitempty"`
	// Metadata is arbitrary JSON stored with the session and echoed in webhooks.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// CreateSessionResponse is what Didit returns.
type CreateSessionResponse struct {
	SessionID     string `json:"session_id"`
	SessionNumber int    `json:"session_number"`
	VendorData    string `json:"vendor_data"`
	Status        string `json:"status"`
	WorkflowID    string `json:"workflow_id"`
	Callback      string `json:"callback"`
	// URL is the verification link you send to your user. If a custom domain
	// is configured, this is https://verify.yourdomain.com/session/...
	URL string `json:"url"`
	// SessionToken is the credential the native SDK needs. Never expose it
	// to the frontend unless you are using the SDK.
	SessionToken string `json:"session_token"`
}

// CreateSession creates a verification session and returns the shareable link.
func (c *Client) CreateSession(ctx context.Context, req CreateSessionRequest) (*CreateSessionResponse, error) {
	if req.WorkflowID == "" {
		req.WorkflowID = c.cfg.WorkflowID
	}
	if req.WorkflowID == "" {
		return nil, errors.New("didit: no workflow ID supplied and no default configured")
	}
	var out CreateSessionResponse
	if err := c.doJSON(ctx, http.MethodPost, "/session/", req, &out); err != nil {
		return nil, err
	}
	if out.URL == "" {
		return nil, errors.New("didit: session created but no URL returned")
	}
	return &out, nil
}

// CreateLink is a convenience wrapper that creates a session and returns
// only the verification URL.
func (c *Client) CreateLink(ctx context.Context, vendorData, callbackURL string) (string, error) {
	resp, err := c.CreateSession(ctx, CreateSessionRequest{
		VendorData: vendorData,
		Callback:   callbackURL,
	})
	if err != nil {
		return "", err
	}
	return resp.URL, nil
}

// ── List sessions ──────────────────────────────────────────────────────────

// ListSessionsParams filters the GET /sessions/ query.
type ListSessionsParams struct {
	SessionKind string // "user" (default), "business", "all"
	Status      string // comma-separated: "Approved,In Review"
	DateFrom    string // YYYY-MM-DD
	DateTo      string // YYYY-MM-DD
	VendorData  string // filter by your own user identifier
	Limit       int    // page size
	Offset      int    // pagination offset
}

// SessionSummary is one row in the session list.
type SessionSummary struct {
	SessionID     string `json:"session_id"`
	SessionKind   string `json:"session_kind"` // "user" or "business"
	SessionNumber int    `json:"session_number"`
	Status        string `json:"status"`
	VendorData    string `json:"vendor_data"`
	WorkflowID    string `json:"workflow_id"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

// PaginatedSessions is the list envelope returned by GET /sessions/.
type PaginatedSessions struct {
	Count    int              `json:"count"`
	Next     *string          `json:"next"`
	Previous *string          `json:"previous"`
	Results  []SessionSummary `json:"results"`
}

// ListSessions queries and filters sessions. Use the Next / Previous links
// in the response to paginate.
func (c *Client) ListSessions(ctx context.Context, p ListSessionsParams) (*PaginatedSessions, error) {
	q := url.Values{}
	if p.SessionKind != "" {
		q.Set("session_kind", p.SessionKind)
	}
	if p.Status != "" {
		q.Set("status", p.Status)
	}
	if p.DateFrom != "" {
		q.Set("date_from", p.DateFrom)
	}
	if p.DateTo != "" {
		q.Set("date_to", p.DateTo)
	}
	if p.VendorData != "" {
		q.Set("vendor_data", p.VendorData)
	}
	if p.Limit > 0 {
		q.Set("limit", strconv.Itoa(p.Limit))
	}
	if p.Offset > 0 {
		q.Set("offset", strconv.Itoa(p.Offset))
	}

	var out PaginatedSessions
	if err := c.doJSON(ctx, http.MethodGet, "/sessions/"+buildQuery(q), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ── Update session status ──────────────────────────────────────────────────

// UpdateStatusRequest is the body for PATCH /session/{id}/update-status/.
type UpdateStatusRequest struct {
	NewStatus string `json:"new_status"` // Approved, Declined, Resubmitted
	Comment   string `json:"comment,omitempty"`
	// NodesToResubmit is required when NewStatus is "Resubmitted".
	NodesToResubmit []ResubmitNode `json:"nodes_to_resubmit,omitempty"`
	// Optional email notification when requesting resubmission.
	SendEmail     bool   `json:"send_email,omitempty"`
	EmailAddress  string `json:"email_address,omitempty"`
	EmailLanguage string `json:"email_language,omitempty"`
}

// ResubmitNode identifies one feature node to re-open.
type ResubmitNode struct {
	NodeID  string `json:"node_id"`
	Feature string `json:"feature"` // OCR, LIVENESS, FACE_MATCH, AML, …
}

// UpdateStatusResponse is the minimal body returned by update-status.
type UpdateStatusResponse struct {
	SessionID string `json:"session_id"`
}

// UpdateSessionStatus manually overrides the final decision of a session.
// Valid transitions: Approve, Decline, or request Resubmission.
func (c *Client) UpdateSessionStatus(ctx context.Context, sessionID string, req UpdateStatusRequest) (*UpdateStatusResponse, error) {
	if sessionID == "" {
		return nil, errors.New("didit: sessionID is required")
	}
	var out UpdateStatusResponse
	if err := c.doJSON(ctx, http.MethodPatch,
		"/session/"+url.PathEscape(sessionID)+"/update-status/", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ── Delete session ─────────────────────────────────────────────────────────

// DeleteSessionRequest controls what happens to the face biometric data.
type DeleteSessionRequest struct {
	// RetainFaceEmbeddings overrides the application's face_retention_policy.
	RetainFaceEmbeddings *bool `json:"retain_face_embeddings,omitempty"`
	// FaceRetentionDays is required when retaining, unless the application
	// already sets a default.
	FaceRetentionDays int `json:"face_retention_days,omitempty"`
	// FaceRetentionDeadline is an optional hard expiry (ISO 8601).
	FaceRetentionDeadline string `json:"face_retention_deadline,omitempty"`
	// DeletionInstruction is "operational_session_delete" (default) or
	// "privacy_erasure".
	DeletionInstruction string `json:"deletion_instruction,omitempty"`
	// InstructionID is your own durable reference for this deletion.
	InstructionID string `json:"instruction_id,omitempty"`
}

// DeleteSessionResponse reports the outcome of the deletion.
type DeleteSessionResponse struct {
	SessionID             string  `json:"session_id"`
	SessionNumber         int     `json:"session_number"`
	FaceRetentionOutcome  string  `json:"face_retention_outcome"`
	BiometricTemplateUUID *string `json:"biometric_template_uuid"`
}

// DeleteSession permanently deletes a session and its data. Pass nil for
// req to use the application's default retention policy.
func (c *Client) DeleteSession(ctx context.Context, sessionID string, req *DeleteSessionRequest) (*DeleteSessionResponse, error) {
	if sessionID == "" {
		return nil, errors.New("didit: sessionID is required")
	}
	// DELETE with an optional JSON body. If req is nil we still need an
	// empty body so Go does not send a nil Content-Length.
	var body any
	if req != nil {
		body = req
	}
	var out DeleteSessionResponse
	if err := c.doJSON(ctx, http.MethodDelete,
		"/session/"+url.PathEscape(sessionID)+"/delete/", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ── Decision payload (fully typed) ─────────────────────────────────────────

// Decision is the complete verification result for a session.
type Decision struct {
	SessionID   string `json:"session_id"`
	SessionKind string `json:"session_kind"`
	Status      string `json:"status"`
	VendorData  string `json:"vendor_data"`
	WorkflowID  string `json:"workflow_id"`
	CreatedAt   int64  `json:"created_at"`

	IDVerifications  []IDVerification  `json:"id_verifications"`
	NFCVerifications []NFCVerification `json:"nfc_verifications"`
	LivenessChecks   []LivenessCheck   `json:"liveness_checks"`
	FaceMatches      []FaceMatch       `json:"face_matches"`
	AMLScreenings    []AMLScreening    `json:"aml_screenings"`

	POAVerifications      []map[string]any `json:"poa_verifications"`
	PhoneVerifications    []map[string]any `json:"phone_verifications"`
	EmailVerifications    []map[string]any `json:"email_verifications"`
	IPAnalyses            []map[string]any `json:"ip_analyses"`
	DatabaseValidations   []map[string]any `json:"database_validations"`
	QuestionnaireResponse []map[string]any `json:"questionnaire_responses"`
}

// IDVerification is one document read.
type IDVerification struct {
	Status          string `json:"status"`
	DocumentType    string `json:"document_type"`
	DocumentSubtype string `json:"document_subtype"`
	DocumentNumber  string `json:"document_number"`
	PersonalNumber  string `json:"personal_number"`
	PortraitImage   string `json:"portrait_image"`

	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	FullName    string `json:"full_name"`
	DateOfBirth string `json:"date_of_birth"`
	Gender      string `json:"gender"`
	Age         int    `json:"age"`

	IssuingState     string `json:"issuing_state"`
	IssuingStateName string `json:"issuing_state_name"`
	ExpirationDate   string `json:"expiration_date"`
	DateOfIssue      string `json:"date_of_issue"`

	Address          string         `json:"address"`
	FormattedAddress string         `json:"formatted_address"`
	ParsedAddress    map[string]any `json:"parsed_address"`
	PlaceOfBirth     string         `json:"place_of_birth"`
	Nationality      string         `json:"nationality"`
	MaritalStatus    string         `json:"marital_status"`

	NodeID   string    `json:"node_id"`
	Warnings []Warning `json:"warnings"`

	FrontImage     string `json:"front_image"`
	BackImage      string `json:"back_image"`
	FrontVideo     string `json:"front_video"`
	BackVideo      string `json:"back_video"`
	FullFrontImage string `json:"full_front_image"`
	FullBackImage  string `json:"full_back_image"`

	FrontImageQualityScore *ImageQualityScore `json:"front_image_quality_score"`
	BackImageQualityScore  *ImageQualityScore `json:"back_image_quality_score"`

	DocumentLiveness map[string]DocumentLivenessScore `json:"document_liveness"`
}

// ImageQualityScore holds quality metrics for a captured document image.
type ImageQualityScore struct {
	FocusScore             float64 `json:"focus_score"`
	BrightnessScore        float64 `json:"brightness_score"`
	ResolutionScore        float64 `json:"resolution_score"`
	OverallScore           float64 `json:"overall_score"`
	BrightnessIssue        string  `json:"brightness_issue"`
	IsDocumentFullyVisible bool    `json:"is_document_fully_visible"`
}

// DocumentLivenessScore holds one fraud-type score.
type DocumentLivenessScore struct {
	Score            float64 `json:"score"`
	Front            float64 `json:"front"`
	Back             float64 `json:"back"`
	DeclineThreshold float64 `json:"decline_threshold"`
	ReviewThreshold  float64 `json:"review_threshold"`
	Bucket           string  `json:"bucket"`
}

// NFCVerification is one ePassport chip read.
type NFCVerification struct {
	Status             string           `json:"status"`
	PortraitImage      string           `json:"portrait_image"`
	SignatureImage     string           `json:"signature_image"`
	ChipData           *NFCChipData     `json:"chip_data"`
	Authenticity       *NFCAuthenticity `json:"authenticity"`
	CertificateSummary map[string]any   `json:"certificate_summary"`
	NodeID             string           `json:"node_id"`
	IsNFCSkipped       bool             `json:"is_nfc_skipped"`
	SkipReason         string           `json:"skip_reason"`
	Warnings           []Warning        `json:"warnings"`
}

// NFCChipData is the parsed chip payload.
type NFCChipData struct {
	Surname        string `json:"surname"`
	Name           string `json:"name"`
	Country        string `json:"country"`
	Nationality    string `json:"nationality"`
	BirthDate      string `json:"birth_date"`
	ExpiryDate     string `json:"expiry_date"`
	Sex            string `json:"sex"`
	DocumentType   string `json:"document_type"`
	DocumentNumber string `json:"document_number"`
	MRZString      string `json:"mrz_string"`
}

// NFCAuthenticity reports chip integrity.
type NFCAuthenticity struct {
	SODIntegrity bool `json:"sod_integrity"`
	DGIntegrity  bool `json:"dg_integrity"`
}

// LivenessCheck is one liveness capture.
type LivenessCheck struct {
	Status         string          `json:"status"`
	Method         string          `json:"method"`
	Score          float64         `json:"score"`
	ReferenceImage string          `json:"reference_image"`
	VideoURL       string          `json:"video_url"`
	AgeEstimation  float64         `json:"age_estimation"`
	FaceQuality    float64         `json:"face_quality"`
	FaceLuminance  float64         `json:"face_luminance"`
	Matches        []LivenessMatch `json:"matches"`
	NodeID         string          `json:"node_id"`
	Warnings       []Warning       `json:"warnings"`
}

// LivenessMatch is a cross-session face match found during liveness.
type LivenessMatch struct {
	SessionID            string         `json:"session_id"`
	SessionNumber        int            `json:"session_number"`
	SimilarityPercentage float64        `json:"similarity_percentage"`
	VendorData           string         `json:"vendor_data"`
	BiometricTemplateID  string         `json:"biometric_template_id"`
	VerificationDate     string         `json:"verification_date"`
	UserDetails          map[string]any `json:"user_details"`
	MatchImageURL        string         `json:"match_image_url"`
	Status               string         `json:"status"`
	IsBlocklisted        bool           `json:"is_blocklisted"`
	IsAllowlisted        bool           `json:"is_allowlisted"`
	Source               string         `json:"source"`
}

// FaceMatch is a 1:1 comparison (liveness face vs document portrait).
type FaceMatch struct {
	Status               string    `json:"status"`
	Score                float64   `json:"score"`
	SourceImageSessionID string    `json:"source_image_session_id"`
	SourceImage          string    `json:"source_image"`
	TargetImage          string    `json:"target_image"`
	NodeID               string    `json:"node_id"`
	Warnings             []Warning `json:"warnings"`
}

// AMLScreening is one AML execution.
type AMLScreening struct {
	Status     string    `json:"status"`
	TotalHits  int       `json:"total_hits"`
	EntityType string    `json:"entity_type"`
	Score      float64   `json:"score"`
	NodeID     string    `json:"node_id"`
	Hits       []AMLHit  `json:"hits"`
	Warnings   []Warning `json:"warnings"`
}

// AMLHit is one watchlist match.
type AMLHit struct {
	MatchScore      float64  `json:"match_score"`
	RiskScore       float64  `json:"risk_score"`
	ReviewStatus    string   `json:"review_status"`
	Categories      []string `json:"categories"`
	Datasets        []string `json:"datasets"`
	MatchedName     string   `json:"matched_name"`
	MatchedEntityID string   `json:"matched_entity_id"`
	Source          string   `json:"source"`
}

// Warning is the shared risk-signal object returned in every warnings[] array.
type Warning struct {
	Feature          string         `json:"feature"`
	Risk             string         `json:"risk"`
	AdditionalData   map[string]any `json:"additional_data"`
	LogType          string         `json:"log_type"`
	ShortDescription string         `json:"short_description"`
	LongDescription  string         `json:"long_description"`
	NodeID           string         `json:"node_id"`
}

// ── Decision helpers ───────────────────────────────────────────────────────

// PrimaryIDVerification returns the first approved ID verification, or nil.
func (d *Decision) PrimaryIDVerification() *IDVerification {
	for i := range d.IDVerifications {
		if d.IDVerifications[i].Status == "Approved" {
			return &d.IDVerifications[i]
		}
	}
	return nil
}

// PrimaryLivenessCheck returns the first approved liveness check, or nil.
func (d *Decision) PrimaryLivenessCheck() *LivenessCheck {
	for i := range d.LivenessChecks {
		if d.LivenessChecks[i].Status == "Approved" {
			return &d.LivenessChecks[i]
		}
	}
	return nil
}

// PrimaryFaceMatch returns the first approved face match, or nil.
func (d *Decision) PrimaryFaceMatch() *FaceMatch {
	for i := range d.FaceMatches {
		if d.FaceMatches[i].Status == "Approved" {
			return &d.FaceMatches[i]
		}
	}
	return nil
}

// ExtractName returns the OCR name from the first approved ID verification.
func (d *Decision) ExtractName() (firstName, lastName, fullName, dob string, ok bool) {
	id := d.PrimaryIDVerification()
	if id == nil {
		return "", "", "", "", false
	}
	return id.FirstName, id.LastName, id.FullName, id.DateOfBirth, true
}

// ── Get decision ───────────────────────────────────────────────────────────

// GetDecision fetches the full decision for a session. Use this if webhooks
// are not reachable, or as a belt-and-braces check after a webhook.
func (c *Client) GetDecision(ctx context.Context, sessionID string) (*Decision, error) {
	if sessionID == "" {
		return nil, errors.New("didit: sessionID is required")
	}
	var out Decision
	if err := c.doJSON(ctx, http.MethodGet,
		"/session/"+url.PathEscape(sessionID)+"/decision/", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ── Webhook ────────────────────────────────────────────────────────────────

// WebhookEvent is the envelope Didit sends to your webhook endpoint.
type WebhookEvent struct {
	EventID         string         `json:"event_id"`
	SessionID       string         `json:"session_id"`
	Status          string         `json:"status"`
	WebhookType     string         `json:"webhook_type"`
	CreatedAt       int64          `json:"created_at"`
	Timestamp       int64          `json:"timestamp"`
	ApplicationID   string         `json:"application_id"`
	Environment     string         `json:"environment"`
	WorkflowID      string         `json:"workflow_id"`
	WorkflowVersion int            `json:"workflow_version"`
	VendorData      string         `json:"vendor_data"`
	Metadata        map[string]any `json:"metadata"`
	Decision        Decision       `json:"decision"`
}

// VerifyWebhook reads the raw body and headers, verifies the HMAC-SHA256
// signature, checks the timestamp freshness, and returns the parsed event.
// Call this BEFORE json.Unmarshal-ing the body yourself.
func (c *Client) VerifyWebhook(r *http.Request) (*WebhookEvent, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("didit: read webhook body: %w", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))

	tsStr := r.Header.Get("X-Timestamp")
	if tsStr == "" {
		return nil, errors.New("didit: missing X-Timestamp header")
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return nil, errors.New("didit: invalid X-Timestamp")
	}
	now := time.Now().Unix()
	if diff := now - ts; diff > 300 || diff < -300 {
		return nil, fmt.Errorf("didit: webhook timestamp too old (diff %ds)", diff)
	}

	sig := r.Header.Get("X-Signature-V2")
	if sig == "" {
		sig = r.Header.Get("X-Signature")
	}
	if sig == "" {
		return nil, errors.New("didit: missing signature header")
	}

	mac := hmac.New(sha256.New, []byte(c.cfg.WebhookSecret))

	if r.Header.Get("X-Signature-V2") != "" {
		mac.Write([]byte(tsStr + ".")) // V2: timestamp.body
	}
	mac.Write(raw)
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return nil, errors.New("didit: webhook signature mismatch")
	}

	var evt WebhookEvent
	if err := json.Unmarshal(raw, &evt); err != nil {
		return nil, fmt.Errorf("didit: decode webhook: %w", err)
	}
	return &evt, nil
}

// ── PDF reports ────────────────────────────────────────────────────────────

// GenerateSessionPDF renders a compliance-ready PDF for one session and
// returns the raw bytes. The session must be in a final or reviewable status.
func (c *Client) GenerateSessionPDF(ctx context.Context, sessionID string) ([]byte, error) {
	if sessionID == "" {
		return nil, errors.New("didit: sessionID is required")
	}
	return c.doRaw(ctx, http.MethodGet,
		"/session/"+url.PathEscape(sessionID)+"/generate-pdf/")
}

// GenerateUserHistoryPDF renders one PDF bundling every reportable session
// of a user, keyed by vendor_data.
func (c *Client) GenerateUserHistoryPDF(ctx context.Context, vendorData string) ([]byte, error) {
	if vendorData == "" {
		return nil, errors.New("didit: vendorData is required")
	}
	return c.doRaw(ctx, http.MethodGet,
		"/users/"+url.PathEscape(vendorData)+"/generate-pdf/")
}

// ── Share session (reusable KYC) ───────────────────────────────────────────

// ShareSessionRequest mints a short-lived token for a partner application.
type ShareSessionRequest struct {
	// ForApplicationID is the partner's Didit application ID.
	ForApplicationID string `json:"for_application_id"`
	// TTLInSeconds is the token lifetime (60 to 86400). Default: 3600.
	TTLInSeconds int `json:"ttl_in_seconds,omitempty"`
}

// ShareSessionResponse contains the minted token.
type ShareSessionResponse struct {
	ShareToken string `json:"share_token"`
}

// ShareSession mints a short-lived JWT that lets a specific Didit
// application import this finished session.
func (c *Client) ShareSession(ctx context.Context, sessionID string, req ShareSessionRequest) (*ShareSessionResponse, error) {
	if sessionID == "" {
		return nil, errors.New("didit: sessionID is required")
	}
	if req.ForApplicationID == "" {
		return nil, errors.New("didit: ForApplicationID is required")
	}
	var out ShareSessionResponse
	if err := c.doJSON(ctx, http.MethodPost,
		"/session/"+url.PathEscape(sessionID)+"/share/", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ImportSharedSessionRequest redeems a token minted by ShareSession.
type ImportSharedSessionRequest struct {
	ShareToken string `json:"share_token"`
}

// ImportSharedSessionResponse is the imported session summary.
type ImportSharedSessionResponse struct {
	SessionID  string `json:"session_id"`
	VendorData string `json:"vendor_data"`
	Status     string `json:"status"`
}

// ImportSharedSession imports a session shared by a partner application.
func (c *Client) ImportSharedSession(ctx context.Context, req ImportSharedSessionRequest) (*ImportSharedSessionResponse, error) {
	if req.ShareToken == "" {
		return nil, errors.New("didit: ShareToken is required")
	}
	var out ImportSharedSessionResponse
	if err := c.doJSON(ctx, http.MethodPost, "/session/import-shared/", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ── Workflows ──────────────────────────────────────────────────────────────

// Workflow is one workflow version.
type Workflow struct {
	UUID                string  `json:"uuid"`
	WorkflowID          string  `json:"workflow_id"`
	WorkflowLabel       string  `json:"workflow_label"`
	WorkflowType        string  `json:"workflow_type"` // kyc, kyb, biometric_authentication, …
	IsDefault           bool    `json:"is_default"`
	IsArchived          bool    `json:"is_archived"`
	IsWhiteLabelEnabled bool    `json:"is_white_label_enabled"`
	TotalPrice          float64 `json:"total_price"`
	MinPrice            float64 `json:"min_price"`
	MaxPrice            float64 `json:"max_price"`
	Features            string  `json:"features"`
	IsSimpleWorkflow    bool    `json:"is_simple_workflow"`
	IsEditable          bool    `json:"is_editable"`
	WorkflowURL         string  `json:"workflow_url"`
	MaxRetryAttempts    int     `json:"max_retry_attempts"`
}

// PaginatedWorkflows is the list envelope returned by GET /workflows/.
type PaginatedWorkflows struct {
	Count    int        `json:"count"`
	Next     *string    `json:"next"`
	Previous *string    `json:"previous"`
	Results  []Workflow `json:"results"`
}

// ListWorkflows returns every workflow for your application, newest first.
func (c *Client) ListWorkflows(ctx context.Context, limit, offset int) (*PaginatedWorkflows, error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if offset > 0 {
		q.Set("offset", strconv.Itoa(offset))
	}
	var out PaginatedWorkflows
	if err := c.doJSON(ctx, http.MethodGet, "/workflows/"+buildQuery(q), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetWorkflow returns full details of one workflow.
func (c *Client) GetWorkflow(ctx context.Context, workflowUUID string) (*Workflow, error) {
	if workflowUUID == "" {
		return nil, errors.New("didit: workflowUUID is required")
	}
	var out Workflow
	if err := c.doJSON(ctx, http.MethodGet,
		"/workflows/"+url.PathEscape(workflowUUID)+"/", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// WorkflowFeature is one feature module in a workflow definition.
type WorkflowFeature struct {
	Feature string         `json:"feature"` // OCR, LIVENESS, FACE_MATCH, AML, NFC, …
	Config  map[string]any `json:"config,omitempty"`
}

// CreateWorkflowRequest defines a new workflow.
type CreateWorkflowRequest struct {
	WorkflowLabel string            `json:"workflow_label"`
	WorkflowType  string            `json:"workflow_type,omitempty"` // kyc, kyb, …
	IsDefault     bool              `json:"is_default,omitempty"`
	Features      []WorkflowFeature `json:"features"`
}

// CreateWorkflow creates a new workflow and returns its full definition.
func (c *Client) CreateWorkflow(ctx context.Context, req CreateWorkflowRequest) (*Workflow, error) {
	if req.WorkflowLabel == "" {
		return nil, errors.New("didit: WorkflowLabel is required")
	}
	var out Workflow
	if err := c.doJSON(ctx, http.MethodPost, "/workflows/", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateWorkflow patches a workflow. Only the non-zero fields are sent.
func (c *Client) UpdateWorkflow(ctx context.Context, workflowUUID string, req CreateWorkflowRequest) (*Workflow, error) {
	if workflowUUID == "" {
		return nil, errors.New("didit: workflowUUID is required")
	}
	var out Workflow
	if err := c.doJSON(ctx, http.MethodPatch,
		"/workflows/"+url.PathEscape(workflowUUID)+"/", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteWorkflow removes a workflow. Sessions already using it are unaffected.
func (c *Client) DeleteWorkflow(ctx context.Context, workflowUUID string) error {
	if workflowUUID == "" {
		return errors.New("didit: workflowUUID is required")
	}
	return c.doJSON(ctx, http.MethodDelete,
		"/workflows/"+url.PathEscape(workflowUUID)+"/", nil, nil)
}

// ── Users (vendor entities) ────────────────────────────────────────────────

// User is a verified individual entity.
type User struct {
	DiditInternalID  string            `json:"didit_internal_id"`
	VendorData       string            `json:"vendor_data"`
	DisplayName      *string           `json:"display_name"`
	FullName         string            `json:"full_name"`
	DateOfBirth      string            `json:"date_of_birth"`
	EffectiveName    string            `json:"effective_name"`
	Status           string            `json:"status"` // ACTIVE, FLAGGED, BLOCKED
	Metadata         map[string]any    `json:"metadata"`
	PortraitImageURL string            `json:"portrait_image_url"`
	SessionCount     int               `json:"session_count"`
	ApprovedCount    int               `json:"approved_count"`
	DeclinedCount    int               `json:"declined_count"`
	InReviewCount    int               `json:"in_review_count"`
	IssuingStates    []string          `json:"issuing_states"`
	ApprovedEmails   []string          `json:"approved_emails"`
	ApprovedPhones   []string          `json:"approved_phones"`
	Features         map[string]string `json:"features"`
}

// ListUsersParams filters GET /users/.
type ListUsersParams struct {
	Status   string // ACTIVE, FLAGGED, BLOCKED
	Search   string // substring on name or vendor_data
	PageSize int
	Page     int
}

// PaginatedUsers is the list envelope returned by GET /users/.
type PaginatedUsers struct {
	Count    int     `json:"count"`
	Next     *string `json:"next"`
	Previous *string `json:"previous"`
	Results  []User  `json:"results"`
}

// ListUsers returns every user entity for your application.
func (c *Client) ListUsers(ctx context.Context, p ListUsersParams) (*PaginatedUsers, error) {
	q := url.Values{}
	if p.Status != "" {
		q.Set("status", p.Status)
	}
	if p.Search != "" {
		q.Set("search", p.Search)
	}
	if p.PageSize > 0 {
		q.Set("page_size", strconv.Itoa(p.PageSize))
	}
	if p.Page > 0 {
		q.Set("page", strconv.Itoa(p.Page))
	}
	var out PaginatedUsers
	if err := c.doJSON(ctx, http.MethodGet, "/users/"+buildQuery(q), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetUser returns one user by your vendor_data identifier.
func (c *Client) GetUser(ctx context.Context, vendorData string) (*User, error) {
	if vendorData == "" {
		return nil, errors.New("didit: vendorData is required")
	}
	var out User
	if err := c.doJSON(ctx, http.MethodGet,
		"/users/"+url.PathEscape(vendorData)+"/", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateUserRequest defines a new user entity without running a session.
type CreateUserRequest struct {
	VendorData  string         `json:"vendor_data"`
	DisplayName string         `json:"display_name,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// CreateUser creates a user entity. Not idempotent — retrying with the same
// vendor_data returns a conflict.
func (c *Client) CreateUser(ctx context.Context, req CreateUserRequest) (*User, error) {
	if req.VendorData == "" {
		return nil, errors.New("didit: VendorData is required")
	}
	var out User
	if err := c.doJSON(ctx, http.MethodPost, "/users/create/", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateUserRequest patches mutable user fields.
type UpdateUserRequest struct {
	DisplayName *string        `json:"display_name,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
}

// UpdateUser patches a user's mutable profile fields.
func (c *Client) UpdateUser(ctx context.Context, vendorData string, req UpdateUserRequest) (*User, error) {
	if vendorData == "" {
		return nil, errors.New("didit: vendorData is required")
	}
	var out User
	if err := c.doJSON(ctx, http.MethodPatch,
		"/users/"+url.PathEscape(vendorData)+"/", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateUserStatus changes a user's monitoring status.
// Valid values: "ACTIVE", "FLAGGED", "BLOCKED".
func (c *Client) UpdateUserStatus(ctx context.Context, vendorData, status string) (*User, error) {
	if vendorData == "" {
		return nil, errors.New("didit: vendorData is required")
	}
	if status != "ACTIVE" && status != "FLAGGED" && status != "BLOCKED" {
		return nil, fmt.Errorf("didit: invalid status %q (want ACTIVE, FLAGGED, BLOCKED)", status)
	}
	var out User
	if err := c.doJSON(ctx, http.MethodPatch,
		"/users/"+url.PathEscape(vendorData)+"/update-status/",
		map[string]string{"status": status}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// BatchDeleteUsersRequest selects users to delete.
type BatchDeleteUsersRequest struct {
	VendorDataList      []string `json:"vendor_data_list,omitempty"`
	DiditInternalIDList []string `json:"didit_internal_id_list,omitempty"`
	DeleteAll           bool     `json:"delete_all,omitempty"`
}

// BatchDeleteUsersResponse reports how many users were removed.
type BatchDeleteUsersResponse struct {
	Deleted int `json:"deleted"`
}

// BatchDeleteUsers permanently deletes users. Prefer UpdateUserStatus with
// "BLOCKED" for everyday blocking.
func (c *Client) BatchDeleteUsers(ctx context.Context, req BatchDeleteUsersRequest) (*BatchDeleteUsersResponse, error) {
	if len(req.VendorDataList) == 0 && len(req.DiditInternalIDList) == 0 && !req.DeleteAll {
		return nil, errors.New("didit: at least one of VendorDataList, DiditInternalIDList, or DeleteAll is required")
	}
	var out BatchDeleteUsersResponse
	if err := c.doJSON(ctx, http.MethodPost, "/users/delete/", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ── Lists (blocklists, allowlists, custom lists) ───────────────────────────

// List is one blocklist, allowlist, or custom list.
type List struct {
	UUID             string  `json:"uuid"`
	Name             string  `json:"name"`
	Description      string  `json:"description"`
	ListType         string  `json:"list_type"`  // blocklist, allowlist, custom
	EntryType        string  `json:"entry_type"` // face, document, phone, email, …
	IsSystem         bool    `json:"is_system"`
	EntryCount       int     `json:"entry_count"`
	LastEntryAddedAt *string `json:"last_entry_added_at"`
	CreatedAt        string  `json:"created_at"`
	UpdatedAt        string  `json:"updated_at"`
}

// PaginatedLists is the list envelope returned by GET /lists/.
type PaginatedLists struct {
	Count    int     `json:"count"`
	Next     *string `json:"next"`
	Previous *string `json:"previous"`
	Results  []List  `json:"results"`
}

// ListListsParams filters GET /lists/.
type ListListsParams struct {
	ListType  string // blocklist, allowlist, custom
	EntryType string // face, document, phone, email, ip_address, …
}

// ListLists returns every list for your application.
func (c *Client) ListLists(ctx context.Context, p ListListsParams) (*PaginatedLists, error) {
	q := url.Values{}
	if p.ListType != "" {
		q.Set("list_type", p.ListType)
	}
	if p.EntryType != "" {
		q.Set("entry_type", p.EntryType)
	}
	var out PaginatedLists
	if err := c.doJSON(ctx, http.MethodGet, "/lists/"+buildQuery(q), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetList returns one list by UUID.
func (c *Client) GetList(ctx context.Context, listUUID string) (*List, error) {
	if listUUID == "" {
		return nil, errors.New("didit: listUUID is required")
	}
	var out List
	if err := c.doJSON(ctx, http.MethodGet,
		"/lists/"+url.PathEscape(listUUID)+"/", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateListRequest defines a new allowlist or custom list.
type CreateListRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	ListType    string `json:"list_type"`  // allowlist or custom
	EntryType   string `json:"entry_type"` // face, document, phone, email, …
}

// CreateList creates a new list. System blocklists are auto-provisioned and
// cannot be created via the API.
func (c *Client) CreateList(ctx context.Context, req CreateListRequest) (*List, error) {
	if req.Name == "" {
		return nil, errors.New("didit: Name is required")
	}
	if req.ListType != "allowlist" && req.ListType != "custom" {
		return nil, errors.New("didit: ListType must be allowlist or custom")
	}
	if req.EntryType == "" {
		return nil, errors.New("didit: EntryType is required")
	}
	var out List
	if err := c.doJSON(ctx, http.MethodPost, "/lists/", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateListRequest patches a list's name or description.
type UpdateListRequest struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// UpdateList renames or re-describes a list. System lists are immutable.
func (c *Client) UpdateList(ctx context.Context, listUUID string, req UpdateListRequest) (*List, error) {
	if listUUID == "" {
		return nil, errors.New("didit: listUUID is required")
	}
	var out List
	if err := c.doJSON(ctx, http.MethodPatch,
		"/lists/"+url.PathEscape(listUUID)+"/", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteList removes an allowlist or custom list. System blocklists cannot
// be deleted.
func (c *Client) DeleteList(ctx context.Context, listUUID string) error {
	if listUUID == "" {
		return errors.New("didit: listUUID is required")
	}
	return c.doJSON(ctx, http.MethodDelete,
		"/lists/"+url.PathEscape(listUUID)+"/", nil, nil)
}

// ── List entries ───────────────────────────────────────────────────────────

// ListEntry is one entry in a list.
type ListEntry struct {
	UUID                   string         `json:"uuid"`
	Value                  string         `json:"value"`
	DisplayLabel           string         `json:"display_label"`
	Comment                string         `json:"comment"`
	AddedBy                string         `json:"added_by"`
	ReferenceSessionID     *string        `json:"reference_session_id"`
	ReferenceSessionNumber *int           `json:"reference_session_number"`
	ReferenceObjectUUID    *string        `json:"reference_object_uuid"`
	Metadata               map[string]any `json:"metadata"`
	CreatedAt              string         `json:"created_at"`
}

// PaginatedListEntries is the list envelope returned by GET /lists/{id}/entries/.
type PaginatedListEntries struct {
	Count    int         `json:"count"`
	Next     *string     `json:"next"`
	Previous *string     `json:"previous"`
	Results  []ListEntry `json:"results"`
}

// ListEntriesParams filters GET /lists/{id}/entries/.
type ListEntriesParams struct {
	Search   string
	PageSize int
	Page     int
}

// ListEntries returns the entries in a list, with optional search.
func (c *Client) ListEntries(ctx context.Context, listUUID string, p ListEntriesParams) (*PaginatedListEntries, error) {
	if listUUID == "" {
		return nil, errors.New("didit: listUUID is required")
	}
	q := url.Values{}
	if p.Search != "" {
		q.Set("search", p.Search)
	}
	if p.PageSize > 0 {
		q.Set("page_size", strconv.Itoa(p.PageSize))
	}
	if p.Page > 0 {
		q.Set("page", strconv.Itoa(p.Page))
	}
	var out PaginatedListEntries
	if err := c.doJSON(ctx, http.MethodGet,
		"/lists/"+url.PathEscape(listUUID)+"/entries/"+buildQuery(q), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AddEntryRequest adds one entry to a list.
type AddEntryRequest struct {
	// Value is the literal entry (email, phone, IP, document number, …).
	Value string `json:"value,omitempty"`
	// ReferenceSessionID lets Didit auto-extract the right value from a
	// verification session.
	ReferenceSessionID string `json:"reference_session_id,omitempty"`
	// ReferenceObjectUUID + Metadata.ReferenceType link the entry to a
	// transaction or vendor user/business.
	ReferenceObjectUUID string         `json:"reference_object_uuid,omitempty"`
	Metadata            map[string]any `json:"metadata,omitempty"`
	Comment             string         `json:"comment,omitempty"`
	DisplayLabel        string         `json:"display_label,omitempty"`
}

// AddEntry adds an entry to a blocklist, allowlist, or custom list.
func (c *Client) AddEntry(ctx context.Context, listUUID string, req AddEntryRequest) (*ListEntry, error) {
	if listUUID == "" {
		return nil, errors.New("didit: listUUID is required")
	}
	if req.Value == "" && req.ReferenceSessionID == "" {
		return nil, errors.New("didit: Value or ReferenceSessionID is required")
	}
	var out ListEntry
	if err := c.doJSON(ctx, http.MethodPost,
		"/lists/"+url.PathEscape(listUUID)+"/entries/", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteEntry removes one entry from a list. On a system blocklist this
// auto-unblocks the underlying entity.
func (c *Client) DeleteEntry(ctx context.Context, listUUID, entryUUID string) error {
	if listUUID == "" {
		return errors.New("didit: listUUID is required")
	}
	if entryUUID == "" {
		return errors.New("didit: entryUUID is required")
	}
	return c.doJSON(ctx, http.MethodDelete,
		"/lists/"+url.PathEscape(listUUID)+"/entries/"+url.PathEscape(entryUUID)+"/",
		nil, nil)
}

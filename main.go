package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// LSP protocol constants.
const (
	DiagnosticSeverityError       = 1
	DiagnosticSeverityWarning     = 2
	DiagnosticSeverityInformation = 3
	DiagnosticSeverityHint        = 4
)

// Position represents a position in a text document (0-indexed).
type Position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

// Range represents a range in a text document.
type Range struct {
	Start Position `json:"start"`
	End   Position `json:"end"`
}

// DiagnosticRelatedInformation provides additional context for a diagnostic.
type DiagnosticRelatedInformation struct {
	Location struct {
		URI   string `json:"uri"`
		Range Range  `json:"range"`
	} `json:"location"`
	Message string `json:"message"`
}

// Diagnostic represents an LSP diagnostic (finding surfaced in the editor).
type Diagnostic struct {
	Range              Range                          `json:"range"`
	Severity           int                            `json:"severity"`
	Code               string                         `json:"code"`
	CodeDescription    *CodeDescription               `json:"codeDescription,omitempty"`
	Source             string                         `json:"source"`
	Message            string                         `json:"message"`
	Tags               []int                          `json:"tags,omitempty"`
	RelatedInformation []DiagnosticRelatedInformation `json:"relatedInformation,omitempty"`
	Data               map[string]string              `json:"data,omitempty"`
}

// CodeDescription links a diagnostic code to external documentation.
type CodeDescription struct {
	Href string `json:"href"`
}

// PublishDiagnosticsParams is the LSP notification sent to the editor.
type PublishDiagnosticsParams struct {
	URI         string       `json:"uri"`
	Version     int          `json:"version,omitempty"`
	Diagnostics []Diagnostic `json:"diagnostics"`
}

// CodeAction represents an LSP code action (e.g., inline suppression).
type CodeAction struct {
	Title       string         `json:"title"`
	Kind        string         `json:"kind"`
	Diagnostics []Diagnostic   `json:"diagnostics,omitempty"`
	IsPreferred bool           `json:"isPreferred,omitempty"`
	Edit        *WorkspaceEdit `json:"edit,omitempty"`
	Command     *Command       `json:"command,omitempty"`
}

// WorkspaceEdit represents edits applied across the workspace.
type WorkspaceEdit struct {
	Changes map[string][]TextEdit `json:"changes"`
}

// TextEdit represents a text edit in a document.
type TextEdit struct {
	Range   Range  `json:"range"`
	NewText string `json:"newText"`
}

// Command represents an LSP command.
type Command struct {
	Title     string `json:"title"`
	Command   string `json:"command"`
	Arguments []any  `json:"arguments,omitempty"`
}

// Hover represents an LSP hover response.
type Hover struct {
	Contents MarkupContent `json:"contents"`
	Range    *Range        `json:"range,omitempty"`
}

// MarkupContent holds rich text for hover display.
type MarkupContent struct {
	Kind  string `json:"kind"` // "plaintext" or "markdown"
	Value string `json:"value"`
}

// WorkspaceSettings holds editor-side configuration for the nox LSP plugin.
type WorkspaceSettings struct {
	Enabled         bool     `json:"enabled"`
	ScanOnSave      bool     `json:"scanOnSave"`
	ScanOnOpen      bool     `json:"scanOnOpen"`
	SeverityFilter  []string `json:"severityFilter"`
	IgnoredRules    []string `json:"ignoredRules"`
	NoxBinaryPath   string   `json:"noxBinaryPath"`
	AdditionalArgs  []string `json:"additionalArgs"`
	ShowInlineHints bool     `json:"showInlineHints"`
	MaxDiagnostics  int      `json:"maxDiagnostics"`
}

// NoxFinding is a simplified representation of a nox finding used as input.
type NoxFinding struct {
	RuleID      string   `json:"rule_id"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	File        string   `json:"file"`
	StartLine   int      `json:"start_line"`
	EndLine     int      `json:"end_line"`
	StartCol    int      `json:"start_col"`
	EndCol      int      `json:"end_col"`
	Message     string   `json:"message"`
	Remediation string   `json:"remediation,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	References  []string `json:"references,omitempty"`
}

// SeverityToLSP maps nox severity strings to LSP diagnostic severity levels.
func SeverityToLSP(severity string) int {
	switch severity {
	case "critical", "high":
		return DiagnosticSeverityError
	case "medium":
		return DiagnosticSeverityWarning
	case "low":
		return DiagnosticSeverityInformation
	case "info":
		return DiagnosticSeverityHint
	default:
		return DiagnosticSeverityWarning
	}
}

// FindingToDiagnostic converts a nox finding into an LSP diagnostic.
func FindingToDiagnostic(f NoxFinding) Diagnostic {
	diag := Diagnostic{
		Range: Range{
			Start: Position{Line: f.StartLine - 1, Character: f.StartCol},
			End:   Position{Line: f.EndLine - 1, Character: f.EndCol},
		},
		Severity: SeverityToLSP(f.Severity),
		Code:     f.RuleID,
		Source:   "nox",
		Message:  f.Message,
		Data: map[string]string{
			"severity":   f.Severity,
			"confidence": f.Confidence,
		},
	}

	if f.CWE != "" {
		diag.CodeDescription = &CodeDescription{
			Href: fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", f.CWE),
		}
		diag.Data["cwe"] = f.CWE
	}

	return diag
}

// FindingsToPublishParams groups findings by file URI and creates
// PublishDiagnosticsParams for each file.
func FindingsToPublishParams(findings []NoxFinding) []PublishDiagnosticsParams {
	byFile := make(map[string][]Diagnostic)
	for _, f := range findings {
		uri := "file://" + f.File
		byFile[uri] = append(byFile[uri], FindingToDiagnostic(f))
	}

	var params []PublishDiagnosticsParams
	for uri, diags := range byFile {
		params = append(params, PublishDiagnosticsParams{
			URI:         uri,
			Diagnostics: diags,
		})
	}
	return params
}

// CreateSuppressionAction creates an LSP code action that inserts a
// nox:ignore comment above the finding line.
func CreateSuppressionAction(uri string, f NoxFinding) CodeAction {
	suppressionLine := f.StartLine - 1 // 0-indexed, line above finding
	if suppressionLine < 0 {
		suppressionLine = 0
	}

	commentText := fmt.Sprintf("// nox:ignore %s -- <reason>\n", f.RuleID)

	return CodeAction{
		Title: fmt.Sprintf("Suppress %s (nox:ignore)", f.RuleID),
		Kind:  "quickfix",
		Edit: &WorkspaceEdit{
			Changes: map[string][]TextEdit{
				uri: {
					{
						Range: Range{
							Start: Position{Line: suppressionLine, Character: 0},
							End:   Position{Line: suppressionLine, Character: 0},
						},
						NewText: commentText,
					},
				},
			},
		},
		IsPreferred: false,
	}
}

// CreateHoverContent generates rich hover content for a finding.
func CreateHoverContent(f NoxFinding) Hover {
	md := fmt.Sprintf("## %s: %s\n\n", f.RuleID, f.Message)
	md += fmt.Sprintf("**Severity:** %s | **Confidence:** %s\n\n", f.Severity, f.Confidence)

	if f.CWE != "" {
		md += fmt.Sprintf("**CWE:** [%s](https://cwe.mitre.org/data/definitions/%s.html)\n\n", f.CWE, f.CWE)
	}

	if f.Remediation != "" {
		md += fmt.Sprintf("### Remediation\n\n%s\n\n", f.Remediation)
	}

	if len(f.References) > 0 {
		md += "### References\n\n"
		for _, ref := range f.References {
			md += fmt.Sprintf("- %s\n", ref)
		}
	}

	return Hover{
		Contents: MarkupContent{
			Kind:  "markdown",
			Value: md,
		},
		Range: &Range{
			Start: Position{Line: f.StartLine - 1, Character: f.StartCol},
			End:   Position{Line: f.EndLine - 1, Character: f.EndCol},
		},
	}
}

// DefaultWorkspaceSettings returns sensible defaults for the LSP plugin.
func DefaultWorkspaceSettings() WorkspaceSettings {
	return WorkspaceSettings{
		Enabled:         true,
		ScanOnSave:      true,
		ScanOnOpen:      true,
		SeverityFilter:  []string{"critical", "high", "medium"},
		IgnoredRules:    nil,
		NoxBinaryPath:   "nox",
		AdditionalArgs:  nil,
		ShowInlineHints: true,
		MaxDiagnostics:  100,
	}
}

// protoSeverityString converts proto severity to string.
func protoSeverityString(s pluginv1.Severity) string {
	switch s {
	case sdk.SeverityCritical:
		return "critical"
	case sdk.SeverityHigh:
		return "high"
	case sdk.SeverityMedium:
		return "medium"
	case sdk.SeverityLow:
		return "low"
	default:
		return "info"
	}
}

// protoConfidenceString converts proto confidence to string.
func protoConfidenceString(c pluginv1.Confidence) string {
	switch c {
	case sdk.ConfidenceHigh:
		return "high"
	case sdk.ConfidenceMedium:
		return "medium"
	case sdk.ConfidenceLow:
		return "low"
	default:
		return "unknown"
	}
}

// protoToNoxFinding converts a proto Finding to our local NoxFinding type.
func protoToNoxFinding(f *pluginv1.Finding) NoxFinding {
	nf := NoxFinding{
		RuleID:     f.GetRuleId(),
		Severity:   protoSeverityString(f.GetSeverity()),
		Confidence: protoConfidenceString(f.GetConfidence()),
		Message:    f.GetMessage(),
	}
	if loc := f.GetLocation(); loc != nil {
		nf.File = loc.GetFilePath()
		nf.StartLine = int(loc.GetStartLine())
		nf.EndLine = int(loc.GetEndLine())
		nf.StartCol = int(loc.GetStartColumn())
		nf.EndCol = int(loc.GetEndColumn())
	}
	if meta := f.GetMetadata(); meta != nil {
		nf.CWE = meta["cwe"]
	}
	return nf
}

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/lsp", version).
		Capability("lsp", "LSP diagnostics, code actions, and hover for nox findings").
		ToolWithContext("convert_diagnostics", "Convert scan findings to LSP diagnostics format", true).
		Tool("get_settings", "Return default workspace settings for the LSP plugin", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("convert_diagnostics", handleConvertDiagnostics).
		HandleTool("get_settings", handleGetSettings)
}

func handleConvertDiagnostics(_ context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	resp := sdk.NewResponse()

	for _, f := range req.Findings() {
		nf := protoToNoxFinding(f)
		uri := "file://" + nf.File
		diag := FindingToDiagnostic(nf)
		action := CreateSuppressionAction(uri, nf)
		hover := CreateHoverContent(nf)

		diagJSON, _ := json.Marshal(diag)
		actionJSON, _ := json.Marshal(action)
		hoverJSON, _ := json.Marshal(hover)

		fingerprint := f.GetFingerprint()
		if fingerprint == "" {
			fingerprint = fmt.Sprintf("%s:%s:%d", f.GetRuleId(), nf.File, nf.StartLine)
		}

		body := fmt.Sprintf("### Diagnostic\n```json\n%s\n```\n\n### Code Action\n```json\n%s\n```\n\n### Hover\n```json\n%s\n```",
			string(diagJSON), string(actionJSON), string(hoverJSON))

		resp.Enrichment(fingerprint, "lsp-diagnostic", fmt.Sprintf("LSP diagnostic for %s", f.GetRuleId())).
			Body(body).
			WithMetadata("uri", uri).
			WithMetadata("lsp_severity", fmt.Sprintf("%d", diag.Severity)).
			Source("nox/lsp").
			Done()
	}

	return resp.Build(), nil
}

func handleGetSettings(_ context.Context, _ sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	resp := sdk.NewResponse()
	settings := DefaultWorkspaceSettings()
	settingsJSON, _ := json.Marshal(settings)

	resp.Enrichment("workspace-settings", "lsp-settings", "Default LSP workspace settings").
		Body(string(settingsJSON)).
		Source("nox/lsp").
		Done()

	return resp.Build(), nil
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-lsp: %v\n", err)
		os.Exit(1)
	}
}

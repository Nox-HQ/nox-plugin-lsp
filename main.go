// Package main implements the nox-plugin-lsp scaffold.
//
// This plugin provides an LSP (Language Server Protocol) server that surfaces
// nox security findings directly in editors (VS Code, Neovim, etc.) as:
//   - Diagnostics (squiggly underlines with severity)
//   - Code actions (inline suppression via nox:ignore comments)
//   - Hover information (finding details, remediation, CWE references)
//
// This is a scaffold demonstrating the LSP message structures and formatting
// logic. The full implementation would use a proper LSP library (e.g.,
// go-lsp or gopls-style server) and integrate with the nox scan pipeline.
package main

import (
	"encoding/json"
	"fmt"
)

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
	Title       string          `json:"title"`
	Kind        string          `json:"kind"`
	Diagnostics []Diagnostic    `json:"diagnostics,omitempty"`
	IsPreferred bool            `json:"isPreferred,omitempty"`
	Edit        *WorkspaceEdit  `json:"edit,omitempty"`
	Command     *Command        `json:"command,omitempty"`
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
	Enabled          bool     `json:"enabled"`
	ScanOnSave       bool     `json:"scanOnSave"`
	ScanOnOpen       bool     `json:"scanOnOpen"`
	SeverityFilter   []string `json:"severityFilter"`
	IgnoredRules     []string `json:"ignoredRules"`
	NoxBinaryPath    string   `json:"noxBinaryPath"`
	AdditionalArgs   []string `json:"additionalArgs"`
	ShowInlineHints  bool     `json:"showInlineHints"`
	MaxDiagnostics   int      `json:"maxDiagnostics"`
}

// NoxFinding is a simplified representation of a nox finding used as input.
type NoxFinding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	File        string `json:"file"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	StartCol    int    `json:"start_col"`
	EndCol      int    `json:"end_col"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	CWE         string `json:"cwe,omitempty"`
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
//
// In production, this would:
//  1. Receive findings from the nox scan pipeline
//  2. Convert each finding to an LSP Diagnostic
//  3. Send publishDiagnostics notifications to the editor
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
//
// In production, this would:
//  1. Receive a code action request from the editor
//  2. Find matching diagnostics at the cursor position
//  3. Generate a TextEdit that inserts the suppression comment
//  4. Return the code action to the editor
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
//
// In production, this would:
//  1. Receive a hover request at a position with a nox diagnostic
//  2. Look up the full finding detail (remediation, CWE, references)
//  3. Format as markdown for display in the editor
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

func main() {
	fmt.Println("nox-plugin-lsp v0.1.0")
	fmt.Println("Track: developer-experience")
	fmt.Println()
	fmt.Println("Tools:")
	fmt.Println("  publish_diagnostics - Publish findings as LSP diagnostics")
	fmt.Println("  code_action         - Inline suppression via nox:ignore comments")
	fmt.Println("  hover               - Finding details on hover")
	fmt.Println()

	// Demonstrate LSP message formatting with a sample finding.
	sample := NoxFinding{
		RuleID:      "SEC-001",
		Severity:    "high",
		Confidence:  "high",
		File:        "/workspace/src/config.go",
		StartLine:   42,
		EndLine:     42,
		StartCol:    10,
		EndCol:      50,
		Message:     "Hardcoded AWS access key detected",
		Remediation: "Rotate the key immediately and use environment variables or a secret manager.",
		CWE:         "798",
		References:  []string{"https://cwe.mitre.org/data/definitions/798.html", "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"},
	}

	fmt.Println("Sample diagnostic:")
	diag := FindingToDiagnostic(sample)
	diagJSON, _ := json.MarshalIndent(diag, "  ", "  ")
	fmt.Println("  " + string(diagJSON))

	fmt.Println()
	fmt.Println("Sample code action:")
	action := CreateSuppressionAction("file:///workspace/src/config.go", sample)
	actionJSON, _ := json.MarshalIndent(action, "  ", "  ")
	fmt.Println("  " + string(actionJSON))

	fmt.Println()
	fmt.Println("Sample hover:")
	hover := CreateHoverContent(sample)
	hoverJSON, _ := json.MarshalIndent(hover, "  ", "  ")
	fmt.Println("  " + string(hoverJSON))

	fmt.Println()
	fmt.Println("Default workspace settings:")
	settings := DefaultWorkspaceSettings()
	settingsJSON, _ := json.MarshalIndent(settings, "  ", "  ")
	fmt.Println("  " + string(settingsJSON))
}

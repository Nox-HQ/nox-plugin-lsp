package main

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConformance(t *testing.T) {
	srv := buildServer()
	sdk.RunConformance(t, srv)
}

func TestTrackConformance(t *testing.T) {
	srv := buildServer()
	sdk.RunForTrack(t, srv, registry.TrackDeveloperExperience)
}

func TestConvertDiagnosticsWithScanContext(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "convert_diagnostics",
		Input:    input,
		ScanContext: &pluginv1.ScanContext{
			Findings: []*pluginv1.Finding{
				{
					RuleId:      "SEC-001",
					Severity:    sdk.SeverityHigh,
					Confidence:  sdk.ConfidenceHigh,
					Message:     "Hardcoded AWS access key detected",
					Fingerprint: "fp-sec-001",
					Location: &pluginv1.Location{
						FilePath:  "/workspace/config.go",
						StartLine: 42,
						EndLine:   42,
					},
					Metadata: map[string]string{"cwe": "798"},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}

	if len(resp.GetEnrichments()) != 1 {
		t.Fatalf("expected 1 enrichment, got %d", len(resp.GetEnrichments()))
	}

	e := resp.GetEnrichments()[0]
	if e.GetKind() != "lsp-diagnostic" {
		t.Errorf("kind = %q, want lsp-diagnostic", e.GetKind())
	}
	if e.GetSource() != "nox/lsp" {
		t.Errorf("source = %q, want nox/lsp", e.GetSource())
	}
	if !strings.Contains(e.GetBody(), "SEC-001") {
		t.Error("body should contain rule ID")
	}
	if !strings.Contains(e.GetBody(), "nox:ignore") {
		t.Error("body should contain suppression action")
	}
}

func TestConvertDiagnosticsNoContext(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "convert_diagnostics",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}

	if len(resp.GetEnrichments()) != 0 {
		t.Errorf("expected 0 enrichments without scan context, got %d", len(resp.GetEnrichments()))
	}
}

func TestGetSettings(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "get_settings",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}

	if len(resp.GetEnrichments()) != 1 {
		t.Fatalf("expected 1 enrichment, got %d", len(resp.GetEnrichments()))
	}

	e := resp.GetEnrichments()[0]
	if e.GetKind() != "lsp-settings" {
		t.Errorf("kind = %q, want lsp-settings", e.GetKind())
	}

	var settings WorkspaceSettings
	if err := json.Unmarshal([]byte(e.GetBody()), &settings); err != nil {
		t.Fatalf("failed to parse settings: %v", err)
	}
	if !settings.Enabled {
		t.Error("Enabled should be true")
	}
	if settings.MaxDiagnostics != 100 {
		t.Errorf("MaxDiagnostics = %d, want 100", settings.MaxDiagnostics)
	}
}

// --- Domain logic unit tests (preserved from Gen 1) ---

func TestSeverityToLSP(t *testing.T) {
	tests := []struct {
		severity string
		want     int
	}{
		{"critical", DiagnosticSeverityError},
		{"high", DiagnosticSeverityError},
		{"medium", DiagnosticSeverityWarning},
		{"low", DiagnosticSeverityInformation},
		{"info", DiagnosticSeverityHint},
		{"unknown", DiagnosticSeverityWarning},
		{"", DiagnosticSeverityWarning},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := SeverityToLSP(tt.severity)
			if got != tt.want {
				t.Errorf("SeverityToLSP(%q) = %d, want %d", tt.severity, got, tt.want)
			}
		})
	}
}

func TestFindingToDiagnostic(t *testing.T) {
	f := NoxFinding{
		RuleID:     "SEC-001",
		Severity:   "high",
		Confidence: "high",
		File:       "/workspace/config.go",
		StartLine:  42,
		EndLine:    42,
		StartCol:   10,
		EndCol:     50,
		Message:    "Hardcoded secret detected",
		CWE:        "798",
	}

	diag := FindingToDiagnostic(&f)

	if diag.Range.Start.Line != 41 {
		t.Errorf("Start.Line = %d, want 41", diag.Range.Start.Line)
	}
	if diag.Range.Start.Character != 10 {
		t.Errorf("Start.Character = %d, want 10", diag.Range.Start.Character)
	}
	if diag.Range.End.Line != 41 {
		t.Errorf("End.Line = %d, want 41", diag.Range.End.Line)
	}
	if diag.Range.End.Character != 50 {
		t.Errorf("End.Character = %d, want 50", diag.Range.End.Character)
	}
	if diag.Severity != DiagnosticSeverityError {
		t.Errorf("Severity = %d, want %d (Error)", diag.Severity, DiagnosticSeverityError)
	}
	if diag.Code != "SEC-001" {
		t.Errorf("Code = %q, want SEC-001", diag.Code)
	}
	if diag.Source != "nox" {
		t.Errorf("Source = %q, want nox", diag.Source)
	}
	if diag.Message != "Hardcoded secret detected" {
		t.Errorf("Message = %q, want 'Hardcoded secret detected'", diag.Message)
	}
	if diag.CodeDescription == nil {
		t.Fatal("expected CodeDescription with CWE link")
	}
	if !strings.Contains(diag.CodeDescription.Href, "798") {
		t.Errorf("CodeDescription.Href = %q, want CWE-798 link", diag.CodeDescription.Href)
	}
	if diag.Data["severity"] != "high" {
		t.Errorf("Data[severity] = %q, want high", diag.Data["severity"])
	}
	if diag.Data["cwe"] != "798" {
		t.Errorf("Data[cwe] = %q, want 798", diag.Data["cwe"])
	}
}

func TestFindingToDiagnostic_NoCWE(t *testing.T) {
	f := NoxFinding{
		RuleID:    "IAC-002",
		Severity:  "medium",
		File:      "/workspace/Dockerfile",
		StartLine: 1,
		EndLine:   1,
		Message:   "Unpinned base image",
	}

	diag := FindingToDiagnostic(&f)

	if diag.CodeDescription != nil {
		t.Errorf("expected nil CodeDescription when no CWE, got %+v", diag.CodeDescription)
	}
	if diag.Severity != DiagnosticSeverityWarning {
		t.Errorf("Severity = %d, want %d (Warning)", diag.Severity, DiagnosticSeverityWarning)
	}
}

func TestFindingsToPublishParams(t *testing.T) {
	findings := []NoxFinding{
		{RuleID: "SEC-001", File: "/workspace/a.go", StartLine: 1, EndLine: 1, Severity: "high", Message: "secret"},
		{RuleID: "SEC-002", File: "/workspace/a.go", StartLine: 5, EndLine: 5, Severity: "high", Message: "secret2"},
		{RuleID: "IAC-002", File: "/workspace/Dockerfile", StartLine: 1, EndLine: 1, Severity: "medium", Message: "unpinned"},
	}

	params := FindingsToPublishParams(findings)

	if len(params) != 2 {
		t.Fatalf("expected 2 PublishDiagnosticsParams, got %d", len(params))
	}

	totalDiags := 0
	for _, p := range params {
		totalDiags += len(p.Diagnostics)
		if !strings.HasPrefix(p.URI, "file://") {
			t.Errorf("URI %q does not start with file://", p.URI)
		}
	}
	if totalDiags != 3 {
		t.Errorf("total diagnostics = %d, want 3", totalDiags)
	}
}

func TestFindingsToPublishParams_Empty(t *testing.T) {
	params := FindingsToPublishParams(nil)
	if len(params) != 0 {
		t.Errorf("expected 0 params for empty input, got %d", len(params))
	}
}

func TestCreateSuppressionAction(t *testing.T) {
	f := NoxFinding{
		RuleID:    "SEC-001",
		StartLine: 42,
		EndLine:   42,
	}

	action := CreateSuppressionAction("file:///workspace/config.go", &f)

	if !strings.Contains(action.Title, "SEC-001") {
		t.Errorf("Title = %q, should contain SEC-001", action.Title)
	}
	if !strings.Contains(action.Title, "nox:ignore") {
		t.Errorf("Title = %q, should contain nox:ignore", action.Title)
	}
	if action.Kind != "quickfix" {
		t.Errorf("Kind = %q, want quickfix", action.Kind)
	}
	if action.IsPreferred {
		t.Error("suppression should not be preferred action")
	}
	if action.Edit == nil {
		t.Fatal("expected non-nil Edit")
	}
	changes, ok := action.Edit.Changes["file:///workspace/config.go"]
	if !ok {
		t.Fatal("expected changes for file URI")
	}
	if len(changes) != 1 {
		t.Fatalf("expected 1 text edit, got %d", len(changes))
	}

	edit := changes[0]
	if edit.Range.Start.Line != 41 {
		t.Errorf("edit line = %d, want 41 (line above finding)", edit.Range.Start.Line)
	}
	if !strings.Contains(edit.NewText, "nox:ignore SEC-001") {
		t.Errorf("NewText = %q, should contain 'nox:ignore SEC-001'", edit.NewText)
	}
	if !strings.HasSuffix(edit.NewText, "\n") {
		t.Error("NewText should end with newline")
	}
}

func TestCreateSuppressionAction_FirstLine(t *testing.T) {
	f := NoxFinding{
		RuleID:    "IAC-002",
		StartLine: 1,
		EndLine:   1,
	}

	action := CreateSuppressionAction("file:///workspace/Dockerfile", &f)
	changes := action.Edit.Changes["file:///workspace/Dockerfile"]
	if len(changes) != 1 {
		t.Fatalf("expected 1 text edit, got %d", len(changes))
	}

	if changes[0].Range.Start.Line != 0 {
		t.Errorf("edit line = %d, want 0 for first-line finding", changes[0].Range.Start.Line)
	}
}

func TestCreateHoverContent(t *testing.T) {
	f := NoxFinding{
		RuleID:      "SEC-001",
		Severity:    "high",
		Confidence:  "high",
		File:        "/workspace/config.go",
		StartLine:   42,
		EndLine:     42,
		StartCol:    10,
		EndCol:      50,
		Message:     "Hardcoded AWS access key detected",
		Remediation: "Rotate the key and use a secret manager.",
		CWE:         "798",
		References:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
	}

	hover := CreateHoverContent(&f)

	if hover.Contents.Kind != "markdown" {
		t.Errorf("Kind = %q, want markdown", hover.Contents.Kind)
	}

	md := hover.Contents.Value
	if !strings.Contains(md, "SEC-001") {
		t.Error("hover should contain rule ID")
	}
	if !strings.Contains(md, "high") {
		t.Error("hover should contain severity")
	}
	if !strings.Contains(md, "798") {
		t.Error("hover should contain CWE reference")
	}
	if !strings.Contains(md, "Remediation") {
		t.Error("hover should contain remediation section")
	}
	if !strings.Contains(md, "Rotate the key") {
		t.Error("hover should contain remediation text")
	}
	if !strings.Contains(md, "References") {
		t.Error("hover should contain references section")
	}

	if hover.Range == nil {
		t.Fatal("expected non-nil Range")
	}
	if hover.Range.Start.Line != 41 {
		t.Errorf("Range.Start.Line = %d, want 41", hover.Range.Start.Line)
	}
}

func TestCreateHoverContent_Minimal(t *testing.T) {
	f := NoxFinding{
		RuleID:   "IAC-002",
		Severity: "medium",
		Message:  "Unpinned image",
	}

	hover := CreateHoverContent(&f)
	md := hover.Contents.Value

	if !strings.Contains(md, "IAC-002") {
		t.Error("hover should contain rule ID")
	}
	if strings.Contains(md, "CWE") {
		t.Error("hover should not contain CWE when not provided")
	}
	if strings.Contains(md, "Remediation") {
		t.Error("hover should not contain remediation when not provided")
	}
	if strings.Contains(md, "References") {
		t.Error("hover should not contain references when not provided")
	}
}

func TestDefaultWorkspaceSettings(t *testing.T) {
	settings := DefaultWorkspaceSettings()

	if !settings.Enabled {
		t.Error("Enabled should be true by default")
	}
	if !settings.ScanOnSave {
		t.Error("ScanOnSave should be true by default")
	}
	if !settings.ScanOnOpen {
		t.Error("ScanOnOpen should be true by default")
	}
	if settings.NoxBinaryPath != "nox" {
		t.Errorf("NoxBinaryPath = %q, want nox", settings.NoxBinaryPath)
	}
	if settings.MaxDiagnostics != 100 {
		t.Errorf("MaxDiagnostics = %d, want 100", settings.MaxDiagnostics)
	}
	if !settings.ShowInlineHints {
		t.Error("ShowInlineHints should be true by default")
	}

	expected := map[string]bool{"critical": true, "high": true, "medium": true}
	for _, s := range settings.SeverityFilter {
		if !expected[s] {
			t.Errorf("unexpected severity in filter: %q", s)
		}
		delete(expected, s)
	}
	if len(expected) > 0 {
		t.Errorf("missing severities in filter: %v", expected)
	}
}

func TestDiagnosticJSONSerialization(t *testing.T) {
	f := NoxFinding{
		RuleID:    "SEC-001",
		Severity:  "high",
		File:      "/workspace/config.go",
		StartLine: 10,
		EndLine:   10,
		StartCol:  0,
		EndCol:    40,
		Message:   "Secret found",
		CWE:       "798",
	}

	diag := FindingToDiagnostic(&f)
	data, err := json.Marshal(diag)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded Diagnostic
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if decoded.Code != "SEC-001" {
		t.Errorf("decoded Code = %q, want SEC-001", decoded.Code)
	}
	if decoded.Source != "nox" {
		t.Errorf("decoded Source = %q, want nox", decoded.Source)
	}
	if decoded.Severity != DiagnosticSeverityError {
		t.Errorf("decoded Severity = %d, want %d", decoded.Severity, DiagnosticSeverityError)
	}
}

func TestCodeActionJSONSerialization(t *testing.T) {
	f := NoxFinding{RuleID: "SEC-001", StartLine: 10}
	action := CreateSuppressionAction("file:///test.go", &f)

	data, err := json.Marshal(action)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded CodeAction
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if decoded.Kind != "quickfix" {
		t.Errorf("decoded Kind = %q, want quickfix", decoded.Kind)
	}
	if decoded.Edit == nil {
		t.Fatal("decoded Edit should not be nil")
	}
}

// --- helpers ---

func testClient(t *testing.T) pluginv1.PluginServiceClient {
	t.Helper()
	const bufSize = 1024 * 1024

	lis := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, buildServer())

	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return pluginv1.NewPluginServiceClient(conn)
}

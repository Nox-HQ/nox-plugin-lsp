# nox-plugin-lsp

**LSP server that surfaces nox findings as editor diagnostics with inline suppression and hover details.**

<!-- badges -->
![Track: Developer Experience](https://img.shields.io/badge/track-Developer%20Experience-green)
![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)
![Go 1.25+](https://img.shields.io/badge/go-1.25%2B-00ADD8)

---

## Overview

`nox-plugin-lsp` bridges nox security findings into code editors via the Language Server Protocol. It converts nox scan results into LSP diagnostics, provides inline suppression code actions, and renders rich hover content with remediation guidance, CWE links, and severity information.

Security findings are most actionable when they appear directly in the editor, at the moment a developer is looking at the code. This plugin eliminates the context switch between running a CLI scan and navigating to the affected lines. Findings appear as squiggly underlines with severity-appropriate colors (errors for critical/high, warnings for medium, info for low), and developers can suppress false positives with a single code action that inserts a `// nox:ignore <rule-id>` comment.

The plugin belongs to the **Developer Experience** track and operates with a passive risk class -- it reads nox findings and produces LSP protocol output without modifying source files (suppression edits are proposed to the editor, not applied directly).

## Use Cases

### Real-Time Security Feedback in VS Code

A developer opens a Go file that contains a hardcoded API key. The LSP plugin immediately shows a red underline on the offending line with `SEC-042: Hardcoded secret detected` in the problems panel. Hovering over the line shows the CWE link, confidence level, and remediation steps. The developer fixes the issue before even committing.

### Inline Suppression for False Positives

A security rule flags a test fixture file that intentionally contains example credentials. Rather than configuring a global exclusion, the developer uses the code action (lightbulb menu) to insert `// nox:ignore SEC-042 -- test fixture` directly above the line, documenting the suppression reason inline with the code.

### Severity-Based Triage in the Editor

A large codebase has hundreds of findings. The LSP plugin maps nox severities to LSP diagnostic levels -- critical and high findings appear as errors (red), medium as warnings (yellow), and low as information (blue). Developers can filter the problems panel by severity to focus on the most important issues first.

### Hover-Based Security Education

When a developer encounters an unfamiliar finding, hovering over it displays a rich markdown panel with the rule description, remediation guidance, and a clickable CWE link. This turns every finding into a learning opportunity without leaving the editor.

## Tools

| Tool | Description |
|------|-------------|
| `publish_diagnostics` | Convert nox findings into LSP `textDocument/publishDiagnostics` notifications grouped by file URI |
| `code_action` | Generate inline suppression code actions (`// nox:ignore <rule-id>`) for findings |
| `hover` | Render rich markdown hover content with severity, CWE links, remediation, and references |

## Severity Mapping

| Nox Severity | LSP Diagnostic Severity | Editor Display |
|--------------|------------------------|----------------|
| Critical | Error (1) | Red underline |
| High | Error (1) | Red underline |
| Medium | Warning (2) | Yellow underline |
| Low | Information (3) | Blue underline |
| Info | Hint (4) | Faded text |

## Configuration

The plugin accepts workspace settings from the editor:

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enabled` | bool | `true` | Enable/disable the LSP plugin |
| `scanOnSave` | bool | `false` | Trigger scan when a file is saved |
| `scanOnOpen` | bool | `false` | Trigger scan when a file is opened |
| `severityFilter` | string[] | `[]` | Only show findings matching these severities |
| `ignoredRules` | string[] | `[]` | Rule IDs to suppress |
| `noxBinaryPath` | string | `""` | Custom path to nox binary |
| `additionalArgs` | string[] | `[]` | Extra arguments passed to nox scan |
| `showInlineHints` | bool | `false` | Show inline hints for findings |
| `maxDiagnostics` | int | `0` | Maximum diagnostics per file (0 = unlimited) |

## Installation

### Via Nox (recommended)

```bash
nox plugin install nox-hq/nox-plugin-lsp
```

### From source

```bash
git clone https://github.com/nox-hq/nox-plugin-lsp.git
cd nox-plugin-lsp
make build
```

## Development

```bash
# Build the plugin binary
make build

# Run all tests
make test

# Run linter
make lint

# Clean build artifacts
make clean
```

## Architecture

The plugin is built on the Nox plugin SDK and communicates via the Nox plugin protocol over stdio. It implements three tools:

1. **publish_diagnostics** -- Takes an array of nox findings as JSON input, groups them by file URI, converts each finding to an LSP `Diagnostic` with appropriate severity mapping, CWE links, and metadata, then returns `PublishDiagnosticsParams` for each file.

2. **code_action** -- Given a finding and its file URI, generates a `CodeAction` with a `WorkspaceEdit` that inserts a `// nox:ignore <rule-id> -- <reason>` comment on the line above the finding. The edit is proposed to the editor, not applied directly.

3. **hover** -- Renders a `Hover` response with rich markdown content including rule ID, message, severity, confidence, CWE link, remediation guidance, and references.

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/nox-hq/nox-plugin-lsp).

## License

Apache-2.0

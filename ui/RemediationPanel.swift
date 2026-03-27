// MacSentry — RemediationPanel.swift
// Slide-in drawer with step-by-step fix guide + auto-fix

import SwiftUI

struct RemediationPanel: View {
    let finding: ScanFinding
    @Binding var isPresented: Bool
    @State private var showConfirmAutoFix = false
    @State private var fixApplied = false
    @State private var commandCopied = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                // ── Header
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 6) {
                            Image(systemName: finding.severity.icon)
                                .foregroundColor(finding.severity.color)
                            Text(finding.severity.rawValue)
                                .font(.caption.bold())
                                .foregroundColor(finding.severity.color)
                                .padding(.horizontal, 8).padding(.vertical, 3)
                                .background(finding.severity.color.opacity(0.15))
                                .clipShape(Capsule())
                        }
                        Text(finding.title)
                            .font(.headline)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer()
                    Button { isPresented = false } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(.secondary)
                            .font(.title3)
                    }
                    .buttonStyle(.plain)
                }

                Divider()

                // ── Why it matters
                GroupBox(label: Label("Why It Matters", systemImage: "questionmark.circle")) {
                    Text(finding.detail)
                        .font(.body)
                        .padding(.top, 4)
                        .fixedSize(horizontal: false, vertical: true)
                }

                // ── Fix Steps
                GroupBox(label: Label("Remediation Steps", systemImage: "list.number")) {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(Array(finding.fix_steps.enumerated()), id: \.offset) { i, step in
                            HStack(alignment: .top, spacing: 8) {
                                Text("\(i + 1)")
                                    .font(.caption.bold())
                                    .foregroundColor(.white)
                                    .frame(width: 20, height: 20)
                                    .background(Color.accentColor)
                                    .clipShape(Circle())
                                Text(step)
                                    .font(.callout)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                    .padding(.top, 4)
                }

                // ── Terminal Command
                if !finding.command.isEmpty {
                    GroupBox(label: Label("Terminal Command", systemImage: "terminal")) {
                        HStack {
                            Text(finding.command)
                                .font(.system(.footnote, design: .monospaced))
                                .padding(8)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color.secondary.opacity(0.1))
                                .cornerRadius(6)
                            Button {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(finding.command, forType: .string)
                                commandCopied = true
                                DispatchQueue.main.asyncAfter(deadline: .now() + 2) { commandCopied = false }
                            } label: {
                                Image(systemName: commandCopied ? "checkmark" : "doc.on.doc")
                                    .font(.caption)
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.mini)
                        }
                        .padding(.top, 4)
                    }
                }

                // ── MITRE Tag
                if !finding.mitre_tag.isEmpty {
                    HStack {
                        Image(systemName: "tag.fill")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Link("MITRE ATT&CK: \(finding.mitre_tag)",
                             destination: URL(string: "https://attack.mitre.org/techniques/\(finding.mitre_tag.replacingOccurrences(of: ".", with: "/"))")!)
                            .font(.caption)
                    }
                    .foregroundColor(.secondary)
                }

                // ── Auto-Fix Button
                if finding.auto_fixable && !fixApplied {
                    Button(action: { showConfirmAutoFix = true }) {
                        Label("Apply Fix Automatically", systemImage: "wand.and.stars")
                            .frame(maxWidth: .infinity)
                            .font(.subheadline.bold())
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .tint(finding.severity.color)

                    HStack(spacing: 4) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.orange).font(.caption)
                        Text("Requires Admin Password")
                            .font(.caption)
                            .foregroundColor(.orange)
                    }
                } else if fixApplied {
                    Label("Fix applied successfully!", systemImage: "checkmark.circle.fill")
                        .font(.subheadline.bold())
                        .foregroundColor(Color(hex: "#34C759"))
                        .frame(maxWidth: .infinity, alignment: .center)
                }

                Spacer(minLength: 20)
            }
            .padding()
        }
        .background(Color(nsColor: .controlBackgroundColor))
        .confirmationDialog(
            "Apply Fix: \(finding.title)?",
            isPresented: $showConfirmAutoFix,
            titleVisibility: .visible
        ) {
            Button("Apply — Requires Admin Password", role: .destructive) {
                applyAutoFix()
            }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text("This will run:\n\(finding.command)\n\nMacSentry will not make any other changes.")
        }
    }

    private func applyAutoFix() {
        let escaped = finding.command.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let script = "do shell script \"\(escaped)\" with administrator privileges"
        var err: NSDictionary?
        if let sa = NSAppleScript(source: script) {
            sa.executeAndReturnError(&err)
            fixApplied = (err == nil)
        }
    }
}

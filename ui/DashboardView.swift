// MacSentry — DashboardView.swift
// Main dashboard layout — HIG compliant, Light/Dark adaptive

import SwiftUI

struct DashboardView: View {
    @EnvironmentObject var model: ScanStateModel
    @State private var selectedFinding: ScanFinding? = nil
    @State private var showRemediationPanel = false
    @Environment(\.colorScheme) var colorScheme

    var body: some View {
        HSplitView {
            // ── LEFT PANEL — Scan progress
            VStack(spacing: 0) {
                HeaderBar()
                ScoreBar()
                Divider()
                ScrollView {
                    VStack(spacing: 8) {
                        ForEach(orderedSteps) { step in
                            ScanCardView(step: step) { finding in
                                selectedFinding = finding
                                showRemediationPanel = true
                            }
                        }
                    }
                    .padding()
                }
            }
            .frame(minWidth: 460)

            // ── RIGHT PANEL — Findings / Remediation
            if showRemediationPanel, let finding = selectedFinding {
                RemediationPanel(finding: finding, isPresented: $showRemediationPanel)
                    .frame(minWidth: 360, maxWidth: 420)
                    .transition(.move(edge: .trailing))
            } else {
                FindingsSummaryView()
                    .frame(minWidth: 360)
            }
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var orderedSteps: [StepResult] {
        let allSteps = (1...10).compactMap { n in
            model.steps.first { $0.step_number == n }
        }
        return allSteps.isEmpty ? mockSteps : allSteps
    }

    private var mockSteps: [StepResult] {
        (1...10).map { i in
            StepResult(step_number: i, step_name: stepNames[i - 1],
                       description: "Tap Start Scan to begin.",
                       status: "pending", completion_pct: 0,
                       findings: [], risk_level: "SAFE",
                       scan_duration_ms: 0)
        }
    }

    private let stepNames = [
        "System Integrity", "Network Security", "User Authentication",
        "Encryption", "App Permissions", "Malware Indicators",
        "Process Audit", "Startup Persistence", "Browser Security",
        "Patch Compliance"
    ]
}

// MARK: — Header
struct HeaderBar: View {
    @EnvironmentObject var model: ScanStateModel

    var body: some View {
        HStack {
            Label("MacSentry", systemImage: "shield.lefthalf.filled")
                .font(.title2.bold())
                .foregroundColor(.accentColor)
            Spacer()
            Circle()
                .fill(model.isScanning ? Color.green : Color.gray.opacity(0.5))
                .frame(width: 8, height: 8)
            Text(model.isScanning ? "Scanning..." : "Idle")
                .font(.caption)
                .foregroundColor(.secondary)
            Text("v1.0")
                .font(.caption2)
                .foregroundColor(.secondary)
                .padding(.leading, 4)
        }
        .padding(.horizontal)
        .padding(.vertical, 12)
        .background(.regularMaterial)
    }
}

// MARK: — Score Bar
struct ScoreBar: View {
    @EnvironmentObject var model: ScanStateModel

    var body: some View {
        VStack(spacing: 6) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Overall Security Score")
                        .font(.headline)
                    Text(model.overall.map { "Risk: \($0.band)" } ?? "Not scanned yet")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                Spacer()
                Text(model.overall.map { "\($0.score)%" } ?? "--")
                    .font(.system(size: 32, weight: .bold, design: .rounded))
                    .foregroundColor(scoreColor)
            }
            ProgressView(value: Double(model.overall?.score ?? 0), total: 100)
                .tint(scoreColor)
                .scaleEffect(x: 1, y: 1.6)

            HStack(spacing: 16) {
                BadgePill(label: "CRITICAL", count: model.overall?.critical_count ?? 0, color: Color(hex: "#FF3B30"))
                BadgePill(label: "HIGH",     count: model.overall?.high_count ?? 0,     color: Color(hex: "#FF9500"))
                BadgePill(label: "MEDIUM",   count: model.overall?.medium_count ?? 0,   color: Color(hex: "#FFCC00"))
                Spacer()
                Button(action: { model.isScanning ? model.stopScan() : model.startScan() }) {
                    Label(model.isScanning ? "Stop Scan" : "▶ Start Full Scan",
                          systemImage: model.isScanning ? "stop.fill" : "play.fill")
                        .font(.subheadline.bold())
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding()
    }

    private var scoreColor: Color {
        guard let s = model.overall?.score else { return .gray }
        if s >= 90 { return Color(hex: "#34C759") }
        if s >= 70 { return Color(hex: "#FF9500") }
        return Color(hex: "#FF3B30")
    }
}

struct BadgePill: View {
    let label: String; let count: Int; let color: Color
    var body: some View {
        HStack(spacing: 4) {
            Circle().fill(color).frame(width: 8, height: 8)
            Text("\(count) \(label)")
                .font(.caption2.bold())
                .foregroundColor(color)
        }
    }
}

// MacSentry — FindingsSummaryView.swift
// Right panel: aggregated findings sorted by severity

import SwiftUI

struct FindingsSummaryView: View {
    @EnvironmentObject var model: ScanStateModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("All Findings")
                .font(.headline)
                .padding()
            Divider()
            if sortedFindings.isEmpty {
                Spacer()
                VStack(spacing: 12) {
                    Image(systemName: "shield.lefthalf.filled")
                        .font(.system(size: 48))
                        .foregroundColor(.accentColor.opacity(0.4))
                    Text(model.isScanning ? "Scan in progress…" : "Start a scan to see findings")
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity)
                Spacer()
            } else {
                List(sortedFindings) { item in
                    HStack(spacing: 10) {
                        Image(systemName: item.finding.severity.icon)
                            .foregroundColor(item.finding.severity.color)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(item.finding.title)
                                .font(.caption.bold())
                                .lineLimit(2)
                            Text(item.stepName)
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding(.vertical, 2)
                }
                .listStyle(.plain)
            }
        }
    }

    private struct FlatFinding: Identifiable {
        let id = UUID()
        let finding: ScanFinding
        let stepName: String
    }

    private var sortedFindings: [FlatFinding] {
        let order: [Severity] = [.critical, .high, .medium, .low, .safe]
        return model.steps
            .flatMap { s in s.findings.map { FlatFinding(finding: $0, stepName: s.step_name) } }
            .sorted { order.firstIndex(of: $0.finding.severity)! < order.firstIndex(of: $1.finding.severity)! }
    }
}

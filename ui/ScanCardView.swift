// MacSentry — ScanCardView.swift
// Individual scan step card with animated progress bar

import SwiftUI

struct ScanCardView: View {
    let step: StepResult
    let onSelectFinding: (ScanFinding) -> Void

    @State private var isExpanded = false
    @State private var animatedPct: Double = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // ── Card Header
            Button(action: { withAnimation(.spring()) { isExpanded.toggle() } }) {
                HStack(spacing: 12) {
                    ZStack {
                        Circle().fill(statusColor.opacity(0.15))
                            .frame(width: 36, height: 36)
                        Text("\(step.step_number)")
                            .font(.system(size: 14, weight: .bold, design: .rounded))
                            .foregroundColor(statusColor)
                    }

                    VStack(alignment: .leading, spacing: 2) {
                        Text(step.step_name.replacingOccurrences(of: "_", with: " ").capitalized)
                            .font(.subheadline.bold())
                        Text(step.description)
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                    }

                    Spacer()

                    StatusBadge(status: step.status, riskLevel: step.risk_level)

                    Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
            }
            .buttonStyle(.plain)

            // ── Animated Progress Bar
            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    Rectangle()
                        .fill(Color.secondary.opacity(0.15))
                        .frame(height: 3)
                    Rectangle()
                        .fill(statusColor)
                        .frame(width: geo.size.width * (animatedPct / 100.0), height: 3)
                        .animation(.easeInOut(duration: 0.8), value: animatedPct)
                }
            }
            .frame(height: 3)
            .padding(.horizontal, 14)

            // ── Findings List (expanded)
            if isExpanded && !step.findings.isEmpty {
                Divider().padding(.horizontal)
                VStack(spacing: 0) {
                    ForEach(step.findings) { finding in
                        FindingRow(finding: finding) {
                            onSelectFinding(finding)
                        }
                        Divider().padding(.leading, 48)
                    }
                }
            }
        }
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(Color(nsColor: .controlBackgroundColor))
                .shadow(color: .black.opacity(0.05), radius: 4, y: 2)
        )
        .onAppear {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { animatedPct = step.completion_pct }
        }
        .onChange(of: step.completion_pct) { newVal in
            withAnimation { animatedPct = newVal }
        }
    }

    private var statusColor: Color {
        switch step.risk_level {
        case "CRITICAL": return Color(hex: "#FF3B30")
        case "HIGH":     return Color(hex: "#FF9500")
        case "MEDIUM":   return Color(hex: "#FFCC00")
        case "LOW":      return Color(hex: "#34C759")
        default:         return Color.accentColor
        }
    }
}

// MARK: — Finding Row inside expanded card
struct FindingRow: View {
    let finding: ScanFinding
    let onFix: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: finding.severity.icon)
                .foregroundColor(finding.severity.color)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 2) {
                Text(finding.title)
                    .font(.caption.bold())
                    .lineLimit(2)
                Text(finding.detail)
                    .font(.caption2)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            if finding.severity != .safe {
                Button("Fix ▶") { onFix() }
                    .font(.caption.bold())
                    .buttonStyle(.bordered)
                    .controlSize(.mini)
                    .tint(finding.severity.color)
            } else {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundColor(Color(hex: "#34C759"))
                    .font(.subheadline)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
    }
}

// MARK: — Status Badge
struct StatusBadge: View {
    let status: String; let riskLevel: String

    var body: some View {
        Text(label)
            .font(.caption2.bold())
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(badgeColor.opacity(0.15))
            .foregroundColor(badgeColor)
            .clipShape(Capsule())
    }

    private var label: String {
        switch status {
        case "scanning":     return "⟳ Scanning"
        case "issues_found": return "⚠ Issues"
        case "complete":     return "✓ Clean"
        case "skipped":      return "— Skipped"
        default:             return "⏳ Pending"
        }
    }

    private var badgeColor: Color {
        switch riskLevel {
        case "CRITICAL": return Color(hex: "#FF3B30")
        case "HIGH":     return Color(hex: "#FF9500")
        case "MEDIUM":   return Color(hex: "#FFCC00")
        default:         return Color.accentColor
        }
    }
}

// MacSentry — ScanStateModel.swift
// Shared ObservableObject; Python engine speaks JSON over stdout.

import Foundation
import Combine
import SwiftUI

// MARK: — Data Models

enum Severity: String, Codable, CaseIterable {
    case critical = "CRITICAL"
    case high = "HIGH"
    case medium = "MEDIUM"
    case low = "LOW"
    case safe = "SAFE"

    var color: Color {
        switch self {
        case .critical: return Color(hex: "#FF3B30")
        case .high:     return Color(hex: "#FF9500")
        case .medium:   return Color(hex: "#FFCC00")
        case .low:      return Color(hex: "#34C759")
        case .safe:     return Color(hex: "#8E8E93")
        }
    }

    var icon: String {
        switch self {
        case .critical: return "exclamationmark.octagon.fill"
        case .high:     return "exclamationmark.triangle.fill"
        case .medium:   return "exclamationmark.circle.fill"
        case .low:      return "info.circle.fill"
        case .safe:     return "checkmark.shield.fill"
        }
    }
}

struct ScanFinding: Identifiable, Codable {
    let id = UUID()
    var title: String
    var severity: Severity
    var detail: String
    var fix_steps: [String]
    var command: String
    var auto_fixable: Bool
    var mitre_tag: String

    enum CodingKeys: String, CodingKey {
        case title, severity, detail, fix_steps, command, auto_fixable, mitre_tag
    }
}

struct StepResult: Identifiable, Codable {
    let id = UUID()
    var step_number: Int
    var step_name: String
    var description: String
    var status: String
    var completion_pct: Double
    var findings: [ScanFinding]
    var risk_level: String
    var scan_duration_ms: Int

    enum CodingKeys: String, CodingKey {
        case step_number, step_name, description, status,
             completion_pct, findings, risk_level, scan_duration_ms
    }

    var worstSeverity: Severity {
        findings.map(\.severity)
            .min(by: { $0.rawValue < $1.rawValue })
            ?? .safe
    }
}

struct OverallScore: Codable {
    var score: Int
    var band: String
    var critical_count: Int
    var high_count: Int
    var medium_count: Int
    var low_count: Int
    var safe_count: Int
    var total_findings: Int
}

// MARK: — ViewModel

@MainActor
class ScanStateModel: ObservableObject {
    @Published var steps: [StepResult] = []
    @Published var overall: OverallScore? = nil
    @Published var isScanning: Bool = false
    @Published var scanComplete: Bool = false
    @Published var errorMessage: String? = nil

    private var engineProcess: Process?

    // MARK: Start Scan
    func startScan(selectedSteps: [Int]? = nil) {
        guard !isScanning else { return }
        isScanning = true
        scanComplete = false
        errorMessage = nil
        steps = []
        overall = nil

        let process = Process()
        process.executableURL = URL(fileURLWithPath: pythonPath())
        var args = [engineScriptPath(), "--mode", "full"]
        if let sel = selectedSteps {
            args += ["--steps", sel.map(String.init).joined(separator: ",")]
        }
        process.arguments = args

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()

        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty,
                  let line = String(data: data, encoding: .utf8) else { return }
            DispatchQueue.main.async { self?.handleOutput(line) }
        }

        process.terminationHandler = { [weak self] _ in
            DispatchQueue.main.async {
                self?.isScanning = false
                self?.scanComplete = true
            }
        }

        do {
            try process.run()
            engineProcess = process
        } catch {
            isScanning = false
            errorMessage = "Failed to start scanner: \(error.localizedDescription)"
        }
    }

    func stopScan() {
        engineProcess?.terminate()
        isScanning = false
    }

    // MARK: JSON parsing
    private func handleOutput(_ raw: String) {
        for line in raw.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("{") else { continue }
            guard let data = trimmed.data(using: .utf8) else { continue }
            let decoder = JSONDecoder()
            if let step = try? decoder.decode(StepResult.self, from: data) {
                if let idx = steps.firstIndex(where: { $0.step_number == step.step_number }) {
                    steps[idx] = step
                } else {
                    steps.append(step)
                }
                return
            }
            if let wrapper = try? decoder.decode(ScanSummary.self, from: data) {
                overall = wrapper.overall
            }
        }
    }

    private struct ScanSummary: Codable {
        var overall: OverallScore
        var steps: [StepResult]
    }

    // MARK: Helpers
    private func pythonPath() -> String {
        let candidates = ["/opt/homebrew/bin/python3",
                          "/usr/local/bin/python3",
                          "/usr/bin/python3"]
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
            ?? "/usr/bin/python3"
    }

    private func engineScriptPath() -> String {
        Bundle.main.url(forResource: "scanner_engine", withExtension: "py",
                        subdirectory: "Resources/core")?.path
            ?? "\(Bundle.main.resourcePath ?? "")/core/scanner_engine.py"
    }
}

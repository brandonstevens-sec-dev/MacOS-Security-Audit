import Foundation
import SwiftUI

enum AuditError: LocalizedError {
    case scriptNotFound
    case pythonNotFound
    case auditFailed(String)
    case jsonReadFailed(String)

    var errorDescription: String? {
        switch self {
        case .scriptNotFound:
            return "Could not find macos_audit.py. Make sure the GUI is inside the MacOS-Security-Audit repository."
        case .pythonNotFound:
            return "Could not find python3.12. Install Python 3.12 (brew install python@3.12) or create a venv in the project root."
        case .auditFailed(let msg):
            return "Audit failed: \(msg)"
        case .jsonReadFailed(let msg):
            return "Could not read audit results: \(msg)"
        }
    }
}

class AuditRunner: ObservableObject {
    @Published var isRunning = false
    @Published var report: AuditReport?
    @Published var errorMessage: String?
    @Published var lastRunDate: Date?

    func runAudit() {
        guard !isRunning else { return }
        withAnimation(.easeInOut(duration: 0.2)) {
            isRunning = true
            errorMessage = nil
            report = nil
        }

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                let result = try self?.executeAudit()
                DispatchQueue.main.async {
                    withAnimation(.easeInOut(duration: 0.35)) {
                        self?.report = result
                        self?.lastRunDate = Date()
                        self?.isRunning = false
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    withAnimation(.easeInOut(duration: 0.2)) {
                        self?.errorMessage = error.localizedDescription
                        self?.isRunning = false
                    }
                }
            }
        }
    }

    /// Returns the report as pretty-printed JSON data for export.
    func reportJSONData() -> Data? {
        guard let report else { return nil }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try? encoder.encode(report)
    }

    private func executeAudit() throws -> AuditReport {
        let scriptPath = try findScript()
        let pythonPath = try findPython(repoRoot: (scriptPath as NSString).deletingLastPathComponent)

        // Temp file for JSON output
        let jsonURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("macos_audit_gui_\(ProcessInfo.processInfo.processIdentifier).json")

        let process = Process()
        process.executableURL = URL(fileURLWithPath: pythonPath)
        process.arguments = [scriptPath, "--json", jsonURL.path]
        process.currentDirectoryURL = URL(fileURLWithPath: (scriptPath as NSString).deletingLastPathComponent)

        // Ensure Homebrew paths are available (Xcode may have a limited PATH)
        var env = ProcessInfo.processInfo.environment
        let extraPaths = "/opt/homebrew/bin:/usr/local/bin"
        env["PATH"] = extraPaths + ":" + (env["PATH"] ?? "/usr/bin:/bin")
        process.environment = env

        let errPipe = Pipe()
        process.standardOutput = FileHandle.nullDevice
        process.standardError = errPipe

        try process.run()
        process.waitUntilExit()

        // Read JSON output regardless of exit code (partial results are still valid)
        guard FileManager.default.fileExists(atPath: jsonURL.path) else {
            let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            let errText = String(data: errData, encoding: .utf8) ?? "unknown error"
            throw AuditError.auditFailed(errText)
        }

        let data: Data
        do {
            data = try Data(contentsOf: jsonURL)
        } catch {
            throw AuditError.jsonReadFailed(error.localizedDescription)
        }

        try? FileManager.default.removeItem(at: jsonURL)

        let decoder = JSONDecoder()
        return try decoder.decode(AuditReport.self, from: data)
    }

    // MARK: - Locate macos_audit.py

    private func findScript() throws -> String {
        // Method 1: Relative to this source file (development in-repo)
        // AuditRunner.swift is at MacOSAuditGUI/MacOSAuditGUI/AuditRunner.swift
        // Repo root is two directories up from that.
        let sourceDir = (#filePath as NSString).deletingLastPathComponent
        let repoRoot = ((sourceDir as NSString).deletingLastPathComponent as NSString).deletingLastPathComponent
        let devPath = (repoRoot as NSString).appendingPathComponent("macos_audit.py")
        if FileManager.default.fileExists(atPath: devPath) {
            return devPath
        }

        // Method 2: Current working directory
        let cwdPath = FileManager.default.currentDirectoryPath + "/macos_audit.py"
        if FileManager.default.fileExists(atPath: cwdPath) {
            return cwdPath
        }

        // Method 3: Next to the app bundle
        if let bundlePath = Bundle.main.bundlePath as NSString? {
            let appDir = bundlePath.deletingLastPathComponent
            let adjacentPath = (appDir as NSString).appendingPathComponent("macos_audit.py")
            if FileManager.default.fileExists(atPath: adjacentPath) {
                return adjacentPath
            }
        }

        throw AuditError.scriptNotFound
    }

    // MARK: - Locate python3.12

    private func findPython(repoRoot: String) throws -> String {
        // Prefer python3.12 explicitly to avoid falling back to an older
        // system Python that may not support modern syntax.
        let candidates = [
            repoRoot + "/venv/bin/python3",              // project venv from Quick Start
            "/opt/homebrew/bin/python3.12",               // Homebrew Apple Silicon (M1/M2/M3/M4)
            "/usr/local/bin/python3.12",                  // Homebrew Intel / python.org
            "/opt/homebrew/bin/python3",                  // Homebrew generic (Apple Silicon)
            "/usr/local/bin/python3",                     // Homebrew generic (Intel) / python.org
            "/usr/bin/python3",                           // System python (last resort)
        ]
        for path in candidates {
            let resolved = (path as NSString).standardizingPath
            if FileManager.default.fileExists(atPath: resolved) {
                return resolved
            }
        }
        throw AuditError.pythonNotFound
    }
}

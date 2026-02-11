import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct ContentView: View {
    @StateObject private var runner = AuditRunner()

    var body: some View {
        Group {
            if runner.isRunning {
                runningView
            } else if let report = runner.report {
                resultsView(report)
            } else {
                landingView
            }
        }
        .frame(minWidth: 680, minHeight: 450)
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                if runner.report != nil {
                    Button {
                        exportJSON()
                    } label: {
                        Label("Export JSON", systemImage: "square.and.arrow.up")
                    }
                    .help("Export audit report as JSON")
                }

                Button {
                    runner.runAudit()
                } label: {
                    if runner.report != nil {
                        Label("Re-run Audit", systemImage: "arrow.clockwise")
                    } else {
                        Label("Run Audit", systemImage: "play.fill")
                    }
                }
                .disabled(runner.isRunning)
                .help(runner.report != nil ? "Run the audit again" : "Start security audit")
            }
        }
        .alert("Error", isPresented: showError) {
            Button("OK") { runner.errorMessage = nil }
        } message: {
            Text(runner.errorMessage ?? "")
        }
    }

    // MARK: - Landing

    private var landingView: some View {
        VStack(spacing: 20) {
            Spacer()

            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 72))
                .foregroundStyle(.blue.gradient)
                .shadow(color: .blue.opacity(0.3), radius: 12, y: 4)

            Text("macOS Security Audit")
                .font(.largeTitle)
                .fontWeight(.bold)

            Text("Scan your Mac for common security misconfigurations\ncovering firewall, encryption, system integrity, software\nupdates, antivirus, network sharing, and more.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .lineSpacing(2)

            Button {
                runner.runAudit()
            } label: {
                Label("Run Security Audit", systemImage: "play.fill")
                    .font(.title3)
                    .padding(.horizontal, 24)
                    .padding(.vertical, 10)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .padding(.top, 8)

            Text("Read-only \u{2014} no system changes will be made.")
                .font(.caption)
                .foregroundStyle(.tertiary)

            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .transition(.opacity)
    }

    // MARK: - Running

    private var runningView: some View {
        VStack(spacing: 16) {
            ProgressView()
                .controlSize(.large)
            Text("Running security audit\u{2026}")
                .font(.title3)
                .foregroundStyle(.secondary)
            Text("This may take a few seconds.")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .transition(.opacity)
    }

    // MARK: - Results

    private func resultsView(_ report: AuditReport) -> some View {
        List {
            Section {
                SummaryView(summary: report.summary, lastRunDate: runner.lastRunDate)
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(Color.clear)
            }

            Section("Security Checks") {
                ForEach(report.results) { result in
                    CheckRowView(result: result)
                }
            }

            if !report.systemInfo.isEmpty {
                Section("System Information") {
                    ForEach(report.systemInfo.sorted(by: { $0.key < $1.key }), id: \.key) { key, value in
                        HStack {
                            Text(key)
                                .foregroundStyle(.secondary)
                            Spacer()
                            Text(value)
                                .textSelection(.enabled)
                        }
                        .font(.callout)
                    }
                }
            }
        }
        .transition(.opacity)
    }

    // MARK: - Export

    private func exportJSON() {
        guard let data = runner.reportJSONData() else { return }

        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType.json]
        panel.nameFieldStringValue = "security_audit_report.json"
        panel.title = "Export Audit Report"

        guard panel.runModal() == .OK, let url = panel.url else { return }

        do {
            try data.write(to: url)
        } catch {
            runner.errorMessage = "Export failed: \(error.localizedDescription)"
        }
    }

    // MARK: - Helpers

    private var showError: Binding<Bool> {
        Binding(
            get: { runner.errorMessage != nil },
            set: { if !$0 { runner.errorMessage = nil } }
        )
    }
}

#Preview {
    ContentView()
        .frame(width: 780, height: 620)
}

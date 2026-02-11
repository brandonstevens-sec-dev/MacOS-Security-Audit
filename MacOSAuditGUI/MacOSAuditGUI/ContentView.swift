import SwiftUI

struct ContentView: View {
    @StateObject private var runner = AuditRunner()

    var body: some View {
        VStack(spacing: 0) {
            if runner.isRunning {
                runningView
            } else if let report = runner.report {
                resultsView(report)
            } else {
                emptyState
            }
        }
        .frame(minWidth: 600, minHeight: 400)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    runner.runAudit()
                } label: {
                    Label("Run Audit", systemImage: "play.fill")
                }
                .disabled(runner.isRunning)
            }
        }
        .alert("Error", isPresented: showError) {
            Button("OK") { runner.errorMessage = nil }
        } message: {
            Text(runner.errorMessage ?? "")
        }
    }

    // MARK: - States

    private var emptyState: some View {
        VStack(spacing: 16) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
            Text("macOS Security Audit")
                .font(.title2)
                .fontWeight(.semibold)
            Text("Click **Run Audit** to scan your security settings.")
                .foregroundStyle(.secondary)
            Text("No system modifications will be made.")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var runningView: some View {
        VStack(spacing: 16) {
            ProgressView()
                .controlSize(.large)
            Text("Running security audit...")
                .font(.title3)
                .foregroundStyle(.secondary)
            Text("This may take a few seconds.")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func resultsView(_ report: AuditReport) -> some View {
        List {
            Section {
                SummaryView(summary: report.summary)
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
        .frame(width: 700, height: 600)
}

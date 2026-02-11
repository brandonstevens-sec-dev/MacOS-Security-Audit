import SwiftUI

struct SummaryView: View {
    let summary: AuditSummary
    var lastRunDate: Date? = nil

    var body: some View {
        VStack(spacing: 12) {
            // Compliance score
            HStack(alignment: .firstTextBaseline, spacing: 4) {
                Text("\(summary.compliancePercentage, specifier: "%.1f")%")
                    .font(.system(size: 36, weight: .bold, design: .rounded))
                    .foregroundStyle(complianceColor)
                Text("compliance")
                    .font(.title3)
                    .foregroundStyle(.secondary)
            }

            // Stat counters
            HStack(spacing: 16) {
                statBadge(count: summary.passed, label: "passed", color: .green, icon: "checkmark.circle.fill")
                statBadge(count: summary.failed, label: "failed", color: .red, icon: "xmark.circle.fill")
                statBadge(count: summary.warnings, label: "warnings", color: .orange, icon: "exclamationmark.triangle.fill")
                if summary.skipped > 0 {
                    statBadge(count: summary.skipped, label: "skipped", color: .secondary, icon: "forward.fill")
                }
                if summary.errors > 0 {
                    statBadge(count: summary.errors, label: "errors", color: .secondary, icon: "exclamationmark.circle.fill")
                }
            }

            // Timestamp
            if let date = lastRunDate {
                Text("Last run: \(date.formatted(date: .abbreviated, time: .shortened))")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
        }
        .padding()
        .frame(maxWidth: .infinity)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10))
    }

    // MARK: - Helpers

    private func statBadge(count: Int, label: String, color: Color, icon: String) -> some View {
        HStack(spacing: 4) {
            Image(systemName: icon)
                .foregroundStyle(color)
                .font(.caption)
            Text("\(count) \(label)")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }

    private var complianceColor: Color {
        if summary.compliancePercentage >= 80 { return .green }
        if summary.compliancePercentage >= 60 { return .orange }
        return .red
    }
}

#Preview {
    SummaryView(summary: AuditReport.sample.summary, lastRunDate: Date())
        .padding()
        .frame(width: 650)
}

import SwiftUI

struct CheckRowView: View {
    let result: AuditCheckResult
    @State private var isExpanded = false

    var body: some View {
        DisclosureGroup(isExpanded: $isExpanded) {
            VStack(alignment: .leading, spacing: 6) {
                Text(result.detail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)

                if !result.recommendation.isEmpty {
                    Label(result.recommendation, systemImage: "lightbulb")
                        .font(.callout)
                        .foregroundStyle(.orange)
                }
            }
            .padding(.top, 4)
        } label: {
            HStack(spacing: 10) {
                statusIndicator
                VStack(alignment: .leading, spacing: 2) {
                    Text(result.name)
                        .fontWeight(.medium)
                    Text(result.description)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer()
                severityBadge
                statusLabel
            }
        }
    }

    // MARK: - Subviews

    private var statusIndicator: some View {
        Circle()
            .fill(statusColor)
            .frame(width: 10, height: 10)
    }

    private var statusLabel: some View {
        Text(statusText)
            .font(.caption)
            .fontWeight(.semibold)
            .foregroundStyle(statusColor)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(statusColor.opacity(0.12), in: RoundedRectangle(cornerRadius: 4))
    }

    private var severityBadge: some View {
        Text(result.severity.rawValue)
            .font(.system(size: 9, weight: .medium))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 3))
    }

    // MARK: - Helpers

    private var statusColor: Color {
        switch result.status {
        case .pass: return .green
        case .fail: return .red
        case .warning: return .orange
        case .info: return .blue
        case .skipped: return .secondary
        case .error: return .secondary
        }
    }

    private var statusText: String {
        switch result.status {
        case .pass: return "PASS"
        case .fail: return "FAIL"
        case .warning: return "WARN"
        case .info: return "INFO"
        case .skipped: return "SKIP"
        case .error: return "ERROR"
        }
    }
}

#Preview {
    List {
        ForEach(AuditReport.sample.results) { result in
            CheckRowView(result: result)
        }
    }
    .frame(width: 650)
}

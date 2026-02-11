import Foundation

enum CheckStatus: String, Codable {
    case pass = "PASS"
    case fail = "FAIL"
    case warning = "WARNING"
    case info = "INFO"
    case skipped = "SKIPPED"
    case error = "ERROR"
}

enum CheckSeverity: String, Codable {
    case critical = "CRITICAL"
    case high = "HIGH"
    case medium = "MEDIUM"
    case low = "LOW"
    case info = "INFO"
}

struct AuditCheckResult: Codable, Identifiable {
    let name: String
    let status: CheckStatus
    let severity: CheckSeverity
    let description: String
    let detail: String
    let recommendation: String

    var id: String { name }
}

struct AuditSummary: Codable {
    let totalChecks: Int
    let passed: Int
    let failed: Int
    let warnings: Int
    let errors: Int
    let skipped: Int
    let compliancePercentage: Double

    enum CodingKeys: String, CodingKey {
        case totalChecks = "total_checks"
        case passed, failed, warnings, errors, skipped
        case compliancePercentage = "compliance_percentage"
    }
}

struct AuditReport: Codable {
    let systemInfo: [String: String]
    let summary: AuditSummary
    let results: [AuditCheckResult]
    let generatedAt: String?

    enum CodingKeys: String, CodingKey {
        case systemInfo = "system_info"
        case summary, results
        case generatedAt = "generated_at"
    }
}

// MARK: - Sample Data for Previews

extension AuditReport {
    static let sample = AuditReport(
        systemInfo: [
            "Hostname": "MacBook-Pro.local",
            "OS": "macOS 26.2",
            "Architecture": "arm64",
        ],
        summary: AuditSummary(
            totalChecks: 4,
            passed: 2,
            failed: 1,
            warnings: 1,
            errors: 0,
            skipped: 0,
            compliancePercentage: 66.7
        ),
        results: [
            AuditCheckResult(
                name: "Firewall Enabled",
                status: .pass,
                severity: .high,
                description: "Check if the application firewall is enabled.",
                detail: "Firewall is enabled.",
                recommendation: ""
            ),
            AuditCheckResult(
                name: "Gatekeeper",
                status: .pass,
                severity: .critical,
                description: "Check if Gatekeeper is enabled.",
                detail: "Gatekeeper is enabled (assessments enabled).",
                recommendation: ""
            ),
            AuditCheckResult(
                name: "FileVault Encryption",
                status: .fail,
                severity: .critical,
                description: "Check if FileVault full-disk encryption is enabled.",
                detail: "FileVault is Off.",
                recommendation: "Enable FileVault: System Settings > Privacy & Security > FileVault > Turn On"
            ),
            AuditCheckResult(
                name: "Antivirus / Endpoint Protection",
                status: .info,
                severity: .low,
                description: "Check for installed third-party antivirus.",
                detail: "No third-party antivirus detected — relying on built-in macOS protections.",
                recommendation: ""
            ),
        ],
        generatedAt: "2026-02-11T12:00:00+00:00"
    )
}

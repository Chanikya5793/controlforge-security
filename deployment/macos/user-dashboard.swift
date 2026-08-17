import AppKit
import Darwin
import Foundation
import SwiftUI

private let statusURL = URL(fileURLWithPath: "/Library/ControlForge/status/agent-status.json")
private let releaseBuildURL = URL(fileURLWithPath: "/Library/ControlForge/installer/release-build.json")
private let maximumStatusBytes: off_t = 65_536
private let maximumReleaseBuildBytes: off_t = 4_096
private let staleStatusAge: TimeInterval = 300
private let futureClockTolerance: TimeInterval = 60
private let panelBackground = Color(nsColor: .controlBackgroundColor)

enum ReleaseChannel: String, Codable {
    case development
    case staging
    case production

    var label: String { rawValue.capitalized }
}

struct ReleaseBuildIdentity: Codable {
    let schemaVersion: String
    let product: String
    let version: String
    let channel: ReleaseChannel
    let sourceCommit: String
    let sourceTag: String?
    let sourceDirty: Bool
    let accountMode: String
    let accountHost: String?
    let accountPort: Int
    let architectures: [String]
    let minimumMacos: String
    let packageIdentifier: String
    let appBundleIdentifier: String

    var shortCommit: String { String(sourceCommit.prefix(7)) }

    var sourceLabel: String {
        sourceDirty ? "\(shortCommit) with local changes" : shortCommit
    }

    func isValid() -> Bool {
        let validVersion = AccountContract.matches(version, "^[0-9]+\\.[0-9]+\\.[0-9]+$")
        let validCommit = AccountContract.matches(sourceCommit, "^[0-9a-f]{40}$")
        let validTag = sourceTag == nil || AccountContract.bounded(sourceTag ?? "", 64)
        let validAccount: Bool
        if accountMode == "account" {
            validAccount = accountHost.map {
                AccountContract.matches($0, "^[A-Za-z0-9.-]{1,253}$")
            } ?? false
        } else {
            validAccount = accountMode == "manual" && accountHost == nil && accountPort == 443
        }
        let validProduction = channel != .production
            || (!sourceDirty && sourceTag == "v\(version)" && accountMode == "account")
        return schemaVersion == "controlforge-macos-build-v1"
            && product == "ControlForge"
            && validVersion
            && validCommit
            && validTag
            && validAccount
            && (1...65_535).contains(accountPort)
            && architectures == ["arm64"]
            && minimumMacos == "13.0"
            && packageIdentifier == "com.controlforge.agent"
            && appBundleIdentifier == "com.controlforge.user"
            && validProduction
    }
}

enum ReleaseBuildIdentityError: Error {
    case invalid
}

enum ReleaseBuildIdentityDecoder {
    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return decoder
    }()

    static func decode(_ data: Data) throws -> ReleaseBuildIdentity {
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(root.keys) == [
                  "schema_version", "product", "version", "channel", "source_commit",
                  "source_tag", "source_dirty", "account_mode", "account_host", "account_port",
                  "architectures", "minimum_macos", "package_identifier", "app_bundle_identifier",
              ] else {
            throw ReleaseBuildIdentityError.invalid
        }
        let identity = try decoder.decode(ReleaseBuildIdentity.self, from: data)
        guard identity.isValid() else { throw ReleaseBuildIdentityError.invalid }
        return identity
    }
}

private enum LocalReleaseBuildFile {
    static func read() throws -> Data {
        let descriptor = Darwin.open(releaseBuildURL.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw ReleaseBuildIdentityError.invalid }
        defer { Darwin.close(descriptor) }

        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_uid == 0,
              (metadata.st_mode & 0o022) == 0,
              metadata.st_size > 0,
              metadata.st_size <= maximumReleaseBuildBytes else {
            throw ReleaseBuildIdentityError.invalid
        }

        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
        let data = handle.readDataToEndOfFile()
        guard data.count == Int(metadata.st_size) else { throw ReleaseBuildIdentityError.invalid }
        return data
    }

    static func load() -> ReleaseBuildIdentity? {
        try? ReleaseBuildIdentityDecoder.decode(read())
    }
}

struct ControlSummary: Codable {
    let evaluated: Bool
    let total: Int
    let failed: Int
    let degraded: Int?
    let missing: Int?
    let notRunning: Int?

    var hasDetail: Bool { degraded != nil && missing != nil && notRunning != nil }
}

struct DeliverySummary: Codable {
    let status: AgentDeliveryState
    let batchesDelivered: Int
    let batchesPending: Int
    let batchesPendingIsLowerBound: Bool
}

struct TelemetrySummary: Codable {
    let eventsCollected: Int
    let santaEventsCollected: Int
    let santaLinesRejected: Int
}

enum AgentContainmentState: String, Codable {
    case notConfigured = "not_configured"
    case released
    case isolated
    case needsAttention = "needs_attention"

    var label: String {
        switch self {
        case .notConfigured: return "Not configured"
        case .released: return "No restriction active"
        case .isolated: return "Network restricted"
        case .needsAttention: return "Needs attention"
        }
    }
}

struct ContainmentSummary: Codable {
    let state: AgentContainmentState
    let expiresAt: Date?
}

enum AgentRunState: String, Codable {
    case completed
    case failed
}

enum AgentFailureStage: String, Codable {
    case credentialRotation = "credential_rotation"
    case controlCollection = "control_collection"
    case telemetryCollection = "telemetry_collection"
    case delivery
    case actionPolling = "action_polling"

    var label: String {
        switch self {
        case .credentialRotation: return "Credential renewal"
        case .controlCollection: return "Protection checks"
        case .telemetryCollection: return "Activity collection"
        case .delivery: return "Secure delivery"
        case .actionPolling: return "Security-team connection"
        }
    }
}

enum AgentDeliveryState: String, Codable {
    case notAttempted = "not_attempted"
    case succeeded
    case backlogged
    case failed

    var label: String {
        switch self {
        case .notAttempted: return "Not attempted"
        case .succeeded: return "Delivered"
        case .backlogged: return "Waiting to deliver"
        case .failed: return "Delivery interrupted"
        }
    }
}

struct AgentStatus: Codable {
    let schemaVersion: String
    let generatedAt: Date
    let deviceId: String
    let agentVersion: String
    let runStatus: AgentRunState
    let failureStage: AgentFailureStage?
    let controls: ControlSummary
    let delivery: DeliverySummary
    let telemetry: TelemetrySummary
    let containment: ContainmentSummary?
    let actionsProcessed: Int

    func isValid(at now: Date) -> Bool {
        let validFailure = (runStatus == .failed) == (failureStage != nil)
        let validControls = controls.total >= 0 && controls.total <= 10_000
            && controls.failed >= 0 && controls.failed <= controls.total
            && (controls.evaluated || (controls.total == 0 && controls.failed == 0))
        let validDelivery = delivery.batchesDelivered >= 0
            && delivery.batchesDelivered <= 100
            && delivery.batchesPending >= 0
            && delivery.batchesPending <= 100
            && (!delivery.batchesPendingIsLowerBound || delivery.batchesPending == 100)
            && (delivery.status != .succeeded || delivery.batchesPending == 0)
            && (delivery.status != .backlogged || delivery.batchesPending > 0)
            && (delivery.status != .notAttempted || delivery.batchesDelivered == 0)
        let validTelemetry = telemetry.eventsCollected >= 0
            && telemetry.eventsCollected <= 10_000
            && telemetry.santaEventsCollected >= 0
            && telemetry.santaEventsCollected <= telemetry.eventsCollected
            && telemetry.santaLinesRejected >= 0
            && telemetry.santaLinesRejected <= 10_000
        let validActions = actionsProcessed >= 0 && actionsProcessed <= 20
        let validContainment: Bool
        if schemaVersion == "controlforge-agent-status-v1" {
            validContainment = containment == nil
        } else if ["controlforge-agent-status-v2", "controlforge-agent-status-v3"].contains(schemaVersion), let containment {
            validContainment = (containment.state == .isolated)
                == (containment.expiresAt != nil)
        } else {
            validContainment = false
        }
        let validTimestamp = generatedAt <= now.addingTimeInterval(staleStatusAge)
        let validIdentifiers = AccountContract.matches(deviceId, "^[A-Za-z0-9._:-]{1,128}$")
            && AccountContract.bounded(agentVersion, 64)
        let detailCounts = [controls.degraded, controls.missing, controls.notRunning]
        let validDetails = schemaVersion != "controlforge-agent-status-v3"
            ? detailCounts.allSatisfy { $0 == nil }
            : controls.hasDetail && detailCounts.allSatisfy { (0...10_000).contains($0 ?? -1) }
                && controls.failed + (controls.degraded ?? 0) <= controls.total
                && (controls.missing ?? 0) + (controls.notRunning ?? 0) <= controls.failed
                && (controls.evaluated || detailCounts.allSatisfy { $0 == 0 })
        return validFailure && validControls && validDetails && validDelivery && validTelemetry
            && validContainment && validActions && validTimestamp && validIdentifiers
    }
}

enum StatusContractError: Error {
    case invalid
}

enum AgentStatusDecoder {
    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()

    static func decode(_ data: Data, now: Date) throws -> AgentStatus {
        try validateExactContract(data)
        let decoded = try decoder.decode(AgentStatus.self, from: data)
        guard ["controlforge-agent-status-v1", "controlforge-agent-status-v2", "controlforge-agent-status-v3"]
                  .contains(decoded.schemaVersion),
              decoded.isValid(at: now) else {
            throw StatusContractError.invalid
        }
        return decoded
    }

    private static func validateExactContract(_ data: Data) throws {
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw StatusContractError.invalid
        }
        let legacyTopKeys: Set<String> = [
            "schema_version", "generated_at", "device_id", "agent_version", "run_status",
            "failure_stage", "controls", "delivery", "telemetry", "actions_processed",
        ]
        guard let schemaVersion = root["schema_version"] as? String else {
            throw StatusContractError.invalid
        }
        let topKeys = schemaVersion != "controlforge-agent-status-v1"
            ? legacyTopKeys.union(["containment"])
            : legacyTopKeys
        let requiredTopKeys = topKeys.subtracting(["failure_stage"])
        let validContainment = schemaVersion == "controlforge-agent-status-v1"
            ? root["containment"] == nil
            : exactKeys(root["containment"], ["state", "expires_at"])
        guard Set(root.keys).isSubset(of: topKeys),
              requiredTopKeys.isSubset(of: Set(root.keys)),
              validContainment,
              exactKeys(root["controls"], schemaVersion == "controlforge-agent-status-v3"
                  ? ["evaluated", "total", "failed", "degraded", "missing", "not_running"]
                  : ["evaluated", "total", "failed"]),
              exactKeys(root["delivery"], [
                  "status", "batches_delivered", "batches_pending",
                  "batches_pending_is_lower_bound",
              ]),
              exactKeys(root["telemetry"], [
                  "events_collected", "santa_events_collected", "santa_lines_rejected",
              ]) else {
            throw StatusContractError.invalid
        }
    }

    private static func exactKeys(_ value: Any?, _ expected: Set<String>) -> Bool {
        guard let object = value as? [String: Any] else { return false }
        return Set(object.keys) == expected
    }
}

private enum LocalStatusFileError: Error {
    case missing
    case unsafe
    case unreadable
}

private enum LocalStatusFile {
    static func read() throws -> Data {
        let descriptor = Darwin.open(statusURL.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else {
            if errno == ENOENT { throw LocalStatusFileError.missing }
            throw LocalStatusFileError.unreadable
        }
        defer { Darwin.close(descriptor) }

        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0 else {
            throw LocalStatusFileError.unreadable
        }
        guard (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_uid == 0,
              (metadata.st_mode & 0o022) == 0,
              metadata.st_size > 0,
              metadata.st_size <= maximumStatusBytes else {
            throw LocalStatusFileError.unsafe
        }

        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
        let data = handle.readDataToEndOfFile()
        guard data.count == Int(metadata.st_size) else {
            throw LocalStatusFileError.unreadable
        }
        return data
    }
}

enum SnapshotAvailability {
    case loading
    case waiting
    case available
    case unavailable
    case unsupported
}

@MainActor
final class StatusModel: ObservableObject {
    @Published private(set) var status: AgentStatus?
    @Published private(set) var message = "Reading local protection status"
    @Published private(set) var lastRefresh: Date?
    @Published private(set) var availability: SnapshotAvailability = .loading
    private let readStatus: () throws -> Data
    private let clock: () -> Date

    init(readStatus: @escaping () throws -> Data = { try LocalStatusFile.read() },
         clock: @escaping () -> Date = Date.init) {
        self.readStatus = readStatus
        self.clock = clock
    }

    func refresh() {
        do {
            let decoded = try AgentStatusDecoder.decode(readStatus(), now: clock())
            status = decoded
            availability = .available
            setMessage(ProtectionPresentation.make(status: decoded, availability: .available, now: clock()).title)
        } catch LocalStatusFileError.missing {
            status = nil
            availability = .waiting
            setMessage("Waiting for the ControlForge agent to complete its first run.")
        } catch StatusContractError.invalid {
            status = nil
            availability = .unsupported
            setMessage("The installed agent uses an unsupported status format.")
        } catch DecodingError.dataCorrupted {
            status = nil
            availability = .unsupported
            setMessage("The installed agent uses an unsupported status format.")
        } catch {
            status = nil
            availability = .unavailable
            setMessage("Local protection status could not be verified safely.")
        }
        lastRefresh = clock()
    }

    var safeSupportSummary: String {
        guard let status else {
            return "ControlForge support summary\nStatus: \(message)"
        }
        return [
            "ControlForge support summary",
            "Device: \(status.deviceId)",
            "Agent version: \(status.agentVersion)",
            "Report time: \(status.generatedAt.formatted(.iso8601))",
            "Report state: \(ProtectionPresentation.make(status: status, availability: availability, now: clock()).code)",
            "Run: \(status.runStatus.rawValue)",
            "Delivery: \(status.delivery.status.rawValue)",
            "Containment: \(status.containment?.state.rawValue ?? "not reported")",
            "Pending batches: \(pendingDescription(status.delivery))",
            "Security checks failed: \(status.controls.failed)",
            "Security checks degraded: \(status.controls.degraded.map(String.init) ?? "not reported")",
        ].joined(separator: "\n")
    }

    private func pendingDescription(_ delivery: DeliverySummary) -> String {
        delivery.batchesPendingIsLowerBound
            ? "at least \(delivery.batchesPending)"
            : String(delivery.batchesPending)
    }

    private func setMessage(_ value: String) {
        guard message != value else { return }
        message = value
        NSAccessibility.post(
            element: NSApp as Any,
            notification: .announcementRequested,
            userInfo: [
                .announcement: value,
                .priority: NSAccessibilityPriorityLevel.medium.rawValue,
            ]
        )
    }
}

private enum DashboardSection: String, CaseIterable, Identifiable {
    case protection
    case account
    case privacy
    case help

    var id: String { rawValue }

    var label: String {
        switch self {
        case .protection: return "Protection"
        case .account: return "Account"
        case .privacy: return "Data & Privacy"
        case .help: return "Help"
        }
    }

    var symbol: String {
        switch self {
        case .protection: return "shield.checkered"
        case .account: return "person.crop.circle"
        case .privacy: return "hand.raised.fill"
        case .help: return "lifepreserver.fill"
        }
    }
}

enum StatusTone {
    case positive
    case warning
    case critical
    case neutral

    var color: Color {
        switch self {
        case .positive: return .green
        case .warning: return .orange
        case .critical: return .red
        case .neutral: return .secondary
        }
    }

    var symbol: String {
        switch self {
        case .positive: return "checkmark.circle.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .critical: return "xmark.octagon.fill"
        case .neutral: return "minus.circle.fill"
        }
    }
}

struct ProtectionPresentation {
    let code: String
    let label: String
    let title: String
    let explanation: String
    let nextStep: String
    let tone: StatusTone

    static func make(status: AgentStatus?, availability: SnapshotAvailability, now: Date) -> Self {
        func result(_ code: String, _ label: String, _ title: String, _ explanation: String,
                    _ next: String, _ tone: StatusTone = .warning) -> Self {
            Self(code: code, label: label, title: title, explanation: explanation, nextStep: next, tone: tone)
        }
        guard let status else {
            switch availability {
            case .waiting:
                return result("waiting", "Waiting for a report", "This Mac has not reported yet",
                              "There is no local check-in summary to show. Setup may still need to finish.",
                              "Open Account to check setup. If already connected, keep the Mac awake and ask your admin if no report appears.")
            case .unsupported, .unavailable:
                return result("unavailable", "Status unavailable", "We cannot safely read this Mac’s status",
                              "The local summary is missing required information or cannot be verified.",
                              "Refresh once, then share a support summary with your network admin if this continues.", .critical)
            case .loading, .available:
                return result("loading", "Checking", "Reading the latest local report",
                              "This checks the saved report from the background agent; it does not start a scan.",
                              "No action is needed while the report loads.", .neutral)
            }
        }
        let age = now.timeIntervalSince(status.generatedAt)
        if age < -futureClockTolerance {
            return result("clock", "Time mismatch", "This Mac’s time needs checking",
                          "The report is dated in the future, so we cannot tell how recent it is.",
                          "Check Date & Time with your admin, then refresh. This app does not change your clock.")
        }
        if age > staleStatusAge {
            let restriction = status.containment?.state == .isolated || status.containment?.state == .needsAttention
            return result("stale", "Report out of date", "We do not have a recent report",
                          restriction
                            ? "The last report mentioned a network restriction or a restriction problem. Its current state is unknown."
                            : "The background agent has not updated its local report in over five minutes. This alone does not tell us whether the server is offline.",
                          "Keep this Mac awake. Refresh reads the saved report; if its time does not advance, share a support summary with your admin.")
        }
        if status.containment?.state == .needsAttention {
            return result("restriction_attention", "Admin help needed", "Network restriction needs review",
                          "The agent could not verify or reconcile ControlForge’s network restriction safely.",
                          "Contact your network admin using another connection if necessary. Do not change network or security settings to bypass it.", .critical)
        }
        if let containment = status.containment, containment.state == .isolated {
            let overdue = containment.expiresAt.map { $0 <= now } ?? true
            return result(overdue ? "restriction_expired" : "restricted", "Network restricted",
                          overdue ? "Restriction release is not yet confirmed" : "Some network connections are restricted",
                          overdue
                            ? "The recorded release time has passed, but the latest report still says restricted. We cannot assume access has been restored."
                            : "The agent reports an active ControlForge network restriction. A successful upload does not mean normal network access has returned.",
                          "Contact your network admin for guidance. This app cannot release the restriction.")
        }
        if status.runStatus == .failed || status.delivery.status == .failed {
            switch status.failureStage {
            case .credentialRotation:
                return result("credentials", "Admin help needed", "The device credential could not be renewed",
                              "This is the background agent’s credential, not your account password. Later checks in this run did not finish.",
                              "Share a support summary with your admin. Changing your account password will not repair this credential.", .critical)
            case .controlCollection:
                return result("checks_interrupted", "Checks interrupted", "Security checks did not finish",
                              "The agent stopped while checking the installed security components. Their current state is not confirmed.",
                              "Share a support summary with your admin if the next report shows the same issue.", .critical)
            case .telemetryCollection:
                return result("collection_interrupted", "Collection interrupted", "Activity collection did not finish",
                              "The agent stopped while collecting or saving activity. We cannot confirm that this run’s activity was retained.",
                              "Share a support summary with your admin. Do not remove or edit the agent’s files.", .critical)
            case .actionPolling:
                return result("team_connection", "Connection needs review", "The security-team connection was interrupted",
                              "The agent could not finish checking for administrator requests. See Report delivery below for the separate upload result.",
                              "Check your connection and share a support summary if the next report still fails.", .critical)
            case .delivery, nil:
                return result("delivery_failed", "Upload interrupted", "The latest upload did not finish",
                              "Reports still in the local queue will be retried by the background agent. The cause is not available in this summary.",
                              "Keep this Mac online. If the next run also fails, share a support summary with your admin.", .critical)
            }
        }
        if status.controls.failed > 0 || (status.controls.degraded ?? 0) > 0 {
            if (status.controls.missing ?? 0) > 0 {
                return result("component_missing", "Admin help needed", "A required security component was not found",
                              "The configured installation and process checks did not find one or more required components. This is not a malware finding.",
                              "Ask your admin to check installation. Do not download replacement security software from an unfamiliar link.")
            }
            if (status.controls.notRunning ?? 0) > 0 {
                return result("component_stopped", "Admin help needed", "A security component is not running",
                              "Installation evidence was found, but a required process was not detected in the latest check.",
                              "Share a support summary with your admin so they can check the service. This app will not restart it.")
            }
            return result("component_attention", "Checks need review", "A security check needs your admin’s attention",
                          "At least one configured check failed or reported degraded health. Uploading successfully does not resolve that issue.",
                          "Share a support summary with your network admin. They can review the detailed check results.")
        }
        if status.delivery.status == .notAttempted {
            return result("not_sent", "No upload confirmed", "This run did not attempt an upload",
                          "We cannot say that the server received a report from this run.",
                          "Keep the Mac awake and connected. Ask your admin if later reports still show no upload.")
        }
        if status.delivery.batchesPending > 0 {
            return result("backlog", "Reports waiting", "Some reports are waiting to upload",
                          "The agent has saved report batches locally. A batch is a bundle of activity, not a count of threats.",
                          "Keep this Mac connected. The agent retries automatically; ask your admin if the waiting count keeps growing.")
        }
        if status.telemetry.santaLinesRejected > 0 {
            return result("activity_gap", "Some activity unavailable", "Some activity could not be read",
                          "The Santa activity reader reported rejected or unreadable input. This count does not mean that threats were found.",
                          "Share a support summary with your admin if it persists. Do not change permissions or delete logs yourself.")
        }
        if !status.controls.evaluated || status.controls.total == 0 {
            return result("checks_unknown", "Checks unavailable", "Security component health is not confirmed",
                          "The latest run did not include usable security-check results.",
                          "Ask your admin to check the agent’s configuration if the next report is the same.")
        }
        if !status.controls.hasDetail {
            return result("legacy", "Report delivered", "Your latest report reached the server",
                          "This older agent summary does not include degraded-component details, so it cannot confirm that every security check passed.",
                          "Ask your admin about the current agent version. Reporting can continue with the installed version.", .neutral)
        }
        return result("reporting", "Reporting normally", "Your Mac is checking in",
                      "Configured security-component checks passed and the report queue is clear. This does not guarantee that the Mac is threat-free.",
                      "No reporting issue needs your attention. Your network admin reviews security findings separately.", .positive)
    }
}

private struct StatusPill: View {
    let label: String
    let tone: StatusTone

    var body: some View {
        Label(label, systemImage: tone.symbol)
            .font(.headline)
            .foregroundStyle(.primary)
            .padding(.horizontal, 13)
            .padding(.vertical, 8)
            .background(tone.color.opacity(0.13), in: Capsule())
            .overlay(Capsule().stroke(tone.color.opacity(0.35), lineWidth: 1))
            .accessibilityLabel("Protection status: \(label)")
    }
}

private struct ComponentCard: View {
    let icon: String
    let title: String
    let state: String
    let detail: String
    let tone: StatusTone

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .center, spacing: 10) {
                Image(systemName: icon)
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(tone.color)
                    .frame(width: 32, height: 32)
                    .background(tone.color.opacity(0.12), in: RoundedRectangle(cornerRadius: 9))
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.headline)
                    Text(state)
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(tone.color)
                }
            }
            Text(detail)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, minHeight: 128, alignment: .topLeading)
        .padding(16)
        .background(panelBackground, in: RoundedRectangle(cornerRadius: 14))
        .overlay(
            RoundedRectangle(cornerRadius: 14)
                .stroke(.separator.opacity(0.55), lineWidth: 1)
        )
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title): \(state). \(detail)")
    }
}

private struct FactRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 16) {
            Text(label)
                .foregroundStyle(.secondary)
            Spacer(minLength: 20)
            Text(value)
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(label): \(value)")
    }
}

struct ProtectionView: View {
    @ObservedObject var model: StatusModel
    @ObservedObject var accountModel: AccountSetupModel
    var openAccount: () -> Void
    var openHelp: () -> Void

    private var presentation: ProtectionPresentation {
        .make(status: model.status, availability: model.availability, now: Date())
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                pageHeader
                networkCard
                postureCard
                componentSection
                deliverySection
                privacyNotice
            }
            .frame(maxWidth: 920, alignment: .leading)
            .padding(28)
        }
        .navigationTitle("Protection")
    }

    private var networkCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let membership = accountModel.membership,
               model.status == nil || model.status?.deviceId == membership.deviceId {
                Label(membership.networkName, systemImage: "building.2")
                    .font(.headline)
                Text(membership.activationState == "reporting"
                     ? "Enrolled with this network. The latest report below shows current check-in status."
                     : "Setup has not confirmed the first check-in. Open Account to finish connecting.")
                    .foregroundStyle(.secondary)
            } else if accountModel.profile != nil && !accountModel.membershipUnverified && accountModel.membership == nil {
                Text("Connect this Mac to your network").font(.headline)
                Text("Use the initial account details your network admin gave you. You will choose your own password on first sign-in.")
                    .foregroundStyle(.secondary)
            } else {
                Text("Network account details are not verified").font(.headline)
                Text("Open Account to check setup. Existing device reporting, if configured, is shown separately below.")
                    .foregroundStyle(.secondary)
            }
            Button("Open Account", action: openAccount).controlSize(.large)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(panelBackground, in: RoundedRectangle(cornerRadius: 14))
    }

    private var pageHeader: some View {
        HStack(alignment: .center, spacing: 16) {
            Image(systemName: "shield.checkered")
                .font(.system(size: 28, weight: .semibold))
                .foregroundStyle(.tint)
                .frame(width: 52, height: 52)
                .background(.tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 14))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text("This Mac at a glance")
                    .font(.system(.title, design: .rounded, weight: .bold))
                    .accessibilityAddTraits(.isHeader)
                Text(model.status?.deviceId ?? "Waiting for enrollment details")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        }
    }

    private var postureCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .center, spacing: 14) {
                StatusPill(label: presentation.label, tone: presentation.tone)
                Spacer()
                Text(lastVerifiedText)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Text(presentation.title)
                .font(.title2.weight(.semibold))
                .accessibilityAddTraits(.isHeader)
            Text(presentation.explanation)
                .foregroundStyle(.secondary)
            Label(presentation.nextStep, systemImage: "arrow.right.circle.fill")
                .font(.subheadline.weight(.medium))
                .foregroundStyle(.primary)
                .fixedSize(horizontal: false, vertical: true)
            if presentation.code != "reporting" && presentation.code != "loading" {
                Button("Get help & support details", action: openHelp).controlSize(.large)
            }
            Text("Refresh reads the saved report. It does not start a scan, force an upload or change protection settings.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(20)
        .background(presentation.tone.color.opacity(0.08), in: RoundedRectangle(cornerRadius: 16))
        .overlay(
            RoundedRectangle(cornerRadius: 16)
                .stroke(presentation.tone.color.opacity(0.28), lineWidth: 1)
        )
        .accessibilityElement(children: .contain)
    }

    private var componentSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionHeading("What the last report tells us", subtitle: snapshotIsCurrent
                           ? "Local checks and upload status are different from security findings"
                           : "This is historical information, not a current health check")
            LazyVGrid(
                columns: [GridItem(.adaptive(minimum: 230), spacing: 12)],
                spacing: 12
            ) {
                componentCards
            }
        }
    }

    @ViewBuilder
    private var componentCards: some View {
        if let status = model.status {
            ComponentCard(
                icon: "checklist",
                title: "Protection checks",
                state: currentState(controlsState(status.controls)),
                detail: controlsDetail(status.controls),
                tone: currentTone(controlsTone(status.controls))
            )
            ComponentCard(
                icon: "waveform.path.ecg",
                title: "Activity collection",
                state: currentState(telemetryState(status.telemetry)),
                detail: telemetryDetail(status.telemetry),
                tone: currentTone(telemetryTone(status.telemetry))
            )
            ComponentCard(
                icon: "arrow.up.circle",
                title: "Report delivery",
                state: currentState(status.delivery.status.label),
                detail: deliveryDetail(status.delivery),
                tone: currentTone(deliveryTone(status.delivery))
            )
            ComponentCard(
                icon: "network.badge.shield.half.filled",
                title: "Network access",
                state: currentState(status.containment?.state.label ?? "Not reported"),
                detail: containmentDetail(status.containment),
                tone: currentTone(containmentTone(status.containment))
            )
        } else {
            ComponentCard(icon: "checklist", title: "Protection checks", state: "Not available", detail: "Waiting for a verified local summary.", tone: .neutral)
            ComponentCard(icon: "waveform.path.ecg", title: "Activity collection", state: "Not available", detail: "No aggregate collection quality is available yet.", tone: .neutral)
            ComponentCard(icon: "arrow.up.circle", title: "Report delivery", state: "Not available", detail: "No upload or waiting-report count is available yet.", tone: .neutral)
            ComponentCard(icon: "network.badge.shield.half.filled", title: "Network access", state: "Not available", detail: "No verified containment summary is available yet.", tone: .neutral)
        }
    }

    private var deliverySection: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionHeading("Report details", subtitle: "These counts describe activity, not the number of threats")
            VStack(spacing: 0) {
                FactRow(label: "Report time", value: formattedDate(model.status?.generatedAt))
                Divider()
                FactRow(label: "Agent version", value: model.status?.agentVersion ?? "Not available")
                Divider()
                FactRow(label: "Report batches uploaded", value: number(model.status?.delivery.batchesDelivered))
                Divider()
                FactRow(label: "Waiting to deliver", value: pendingText)
                Divider()
                FactRow(label: "Activity items this run", value: number(model.status?.telemetry.eventsCollected))
                if let stage = model.status?.failureStage {
                    Divider()
                    FactRow(label: "Interrupted at", value: stage.label)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .background(panelBackground, in: RoundedRectangle(cornerRadius: 14))
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(.separator.opacity(0.55), lineWidth: 1))
        }
    }

    private var privacyNotice: some View {
        Label {
            Text("This app shows only a redacted local summary. It does not expose raw activity, credentials, investigations, response rationale, or containment controls.")
                .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "lock.shield.fill").foregroundStyle(.secondary)
        }
        .font(.footnote)
        .foregroundStyle(.secondary)
        .padding(.top, 2)
        .accessibilityElement(children: .combine)
    }

    private var lastVerifiedText: String {
        guard let generatedAt = model.status?.generatedAt else { return "Not yet verified" }
        let age = Date().timeIntervalSince(generatedAt)
        if age < -futureClockTolerance { return "Time mismatch" }
        if age < 60 { return "Report from just now" }
        if age < 3_600 { return "Report from \(Int(age / 60)) min ago" }
        if age < 86_400 { return "Report from \(Int(age / 3_600)) hr ago" }
        return "Report from \(Int(age / 86_400)) days ago"
    }

    private var snapshotIsCurrent: Bool {
        guard let status = model.status else { return false }
        return (-futureClockTolerance...staleStatusAge).contains(Date().timeIntervalSince(status.generatedAt))
    }

    private func currentState(_ state: String) -> String {
        snapshotIsCurrent ? state : "Last report: \(state.lowercased())"
    }

    private func currentTone(_ tone: StatusTone) -> StatusTone { snapshotIsCurrent ? tone : .neutral }

    private var pendingText: String {
        guard let delivery = model.status?.delivery else { return "Not available" }
        return delivery.batchesPendingIsLowerBound
            ? "At least \(delivery.batchesPending) batches"
            : "\(delivery.batchesPending) batches"
    }

    private func sectionHeading(_ title: String, subtitle: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.title3.weight(.semibold)).accessibilityAddTraits(.isHeader)
            Text(subtitle).font(.subheadline).foregroundStyle(.secondary)
        }
    }

    private func controlsState(_ controls: ControlSummary) -> String {
        guard controls.evaluated, controls.total > 0 else { return "Not evaluated" }
        if controls.failed > 0 || (controls.degraded ?? 0) > 0 {
            return "\(controls.failed) failed · \(controls.degraded.map(String.init) ?? "unknown") degraded"
        }
        return controls.hasDetail ? "All \(controls.total) checks passed" : "No failures reported"
    }

    private func controlsDetail(_ controls: ControlSummary) -> String {
        guard controls.evaluated, controls.total > 0 else {
            return "The latest run did not include a usable control summary."
        }
        if !controls.hasDetail {
            return "This older summary does not describe degraded health or which components were missing or stopped."
        }
        if controls.failed == 0 && controls.degraded == 0 {
            return "The configured installation, process and heartbeat checks passed. This does not verify malware absence or Santa blocking mode."
        }
        return "Not found: \(controls.missing ?? 0). Not running: \(controls.notRunning ?? 0). Degraded: \(controls.degraded ?? 0). Your admin can review detailed evidence and other failures."
    }

    private func controlsTone(_ controls: ControlSummary) -> StatusTone {
        guard controls.evaluated, controls.total > 0 else { return .warning }
        guard controls.hasDetail else { return .neutral }
        return controls.failed == 0 && controls.degraded == 0 ? .positive : .warning
    }

    private var collectionFinished: Bool {
        ![AgentFailureStage.credentialRotation, .controlCollection, .telemetryCollection]
            .contains(where: { $0 == model.status?.failureStage })
    }

    private func telemetryState(_ telemetry: TelemetrySummary) -> String {
        if !collectionFinished { return "Not completed" }
        if telemetry.santaLinesRejected > 0 { return "Some activity unavailable" }
        return telemetry.eventsCollected > 0 ? "Activity collected" : "No new activity reported"
    }

    private func telemetryDetail(_ telemetry: TelemetrySummary) -> String {
        if !collectionFinished {
            return "This run stopped before activity collection and saving were confirmed. Zero rejected items does not prove collection is working."
        }
        if telemetry.santaLinesRejected > 0 {
            return "The Santa reader reported \(telemetry.santaLinesRejected) rejected or unreadable input items. Ask your admin to check collection; these are not threat counts."
        }
        return "Collected \(telemetry.eventsCollected) activity items, including \(telemetry.santaEventsCollected) from Santa. These counts do not prove Santa is blocking unsafe apps."
    }

    private func telemetryTone(_ telemetry: TelemetrySummary) -> StatusTone {
        guard collectionFinished else { return .neutral }
        if telemetry.santaLinesRejected > 0 { return .warning }
        return telemetry.eventsCollected > 0 ? .positive : .neutral
    }

    private func deliveryDetail(_ delivery: DeliverySummary) -> String {
        switch delivery.status {
        case .succeeded:
            return "At the report time, the local queue was clear. Upload success does not mean that all security checks passed."
        case .backlogged:
            return "\(pendingText.lowercased()) are stored locally and will retry automatically."
        case .failed:
            return pendingText == "0 batches"
                ? "The delivery connection was interrupted. The next run will try again."
                : "Delivery was interrupted; \(pendingText.lowercased()) remain stored for retry."
        case .notAttempted:
            return "The agent has not attempted delivery during this run."
        }
    }

    private func deliveryTone(_ delivery: DeliverySummary) -> StatusTone {
        switch delivery.status {
        case .succeeded: return .positive
        case .backlogged, .notAttempted: return .warning
        case .failed: return .critical
        }
    }

    private func containmentDetail(_ containment: ContainmentSummary?) -> String {
        guard let containment else {
            return "This agent version does not report the privacy-safe containment summary."
        }
        switch containment.state {
        case .notConfigured:
            return "This endpoint is not configured for ControlForge network containment."
        case .released:
            return "ControlForge does not currently own an active network restriction."
        case .isolated:
            if let expiresAt = containment.expiresAt {
                return expiresAt <= Date()
                    ? "The recorded release time has passed. A newer report must confirm whether the restriction was released."
                    : "Automatic release was scheduled for \(formattedDate(expiresAt)). This is not confirmation that release has occurred."
            }
            return "Network access is restricted with a bounded automatic release."
        case .needsAttention:
            return "Containment state could not be reconciled safely. Contact your security team."
        }
    }

    private func containmentTone(_ containment: ContainmentSummary?) -> StatusTone {
        guard let containment else { return .neutral }
        switch containment.state {
        case .released: return .positive
        case .notConfigured: return .neutral
        case .isolated: return .warning
        case .needsAttention: return .critical
        }
    }

    private func number(_ value: Int?) -> String { value.map(String.init) ?? "Not available" }

    private func formattedDate(_ date: Date?) -> String {
        guard let date else { return "Not available" }
        return date.formatted(date: .abbreviated, time: .standard)
    }
}

private struct PrivacyView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                pageHeader
                disclosureCard
                privacyColumns
                containmentNotice
            }
            .frame(maxWidth: 840, alignment: .leading)
            .padding(28)
        }
        .navigationTitle("Data & Privacy")
    }

    private var pageHeader: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Data & Privacy")
                .font(.system(.title, design: .rounded, weight: .bold))
                .accessibilityAddTraits(.isHeader)
            Text("A deliberately narrow view of your Mac's protection status")
                .foregroundStyle(.secondary)
        }
    }

    private var disclosureCard: some View {
        Label {
            VStack(alignment: .leading, spacing: 6) {
                Text("Privacy-safe by design").font(.title3.weight(.semibold))
                Text("The root agent writes a small, redacted summary. This app can read that summary but cannot administer the agent, inspect investigations, or execute security actions.")
                    .foregroundStyle(.secondary)
            }
        } icon: {
            Image(systemName: "hand.raised.fill")
                .font(.title2)
                .foregroundStyle(.tint)
                .accessibilityHidden(true)
        }
        .padding(20)
        .background(.tint.opacity(0.08), in: RoundedRectangle(cornerRadius: 16))
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(.tint.opacity(0.24), lineWidth: 1))
        .accessibilityElement(children: .combine)
    }

    private var privacyColumns: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 280), spacing: 14)], spacing: 14) {
            privacyGroup(
                title: "Shown in this app",
                symbol: "eye.fill",
                items: [
                    "Pass and failure counts for protection checks",
                    "Delivery state and a bounded backlog count",
                    "Aggregate activity and quality counts",
                    "Privacy-safe network containment state and release time",
                    "Agent version, device ID, and last verified time",
                ]
            )
            privacyGroup(
                title: "Kept out of this app",
                symbol: "eye.slash.fill",
                items: [
                    "Collector credentials and access tokens",
                    "Raw events, process arguments, and file contents",
                    "Organization alerts, cases, and tenant information",
                    "Response rationale, approvals, commands, and evidence",
                ]
            )
        }
    }

    private var containmentNotice: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("About network containment", systemImage: "network.badge.shield.half.filled")
                .font(.headline)
            Text("The current agent reports only whether ControlForge containment is unavailable, released, isolated, or needs attention, plus a bounded release time when isolated. Action IDs, rationale, approvals, PF tokens, addresses, commands, and evidence remain hidden. Older agents are shown as not reporting instead of being guessed.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(18)
        .background(panelBackground, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(.separator.opacity(0.55), lineWidth: 1))
        .accessibilityElement(children: .combine)
    }

    private func privacyGroup(title: String, symbol: String, items: [String]) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(title, systemImage: symbol)
                .font(.headline)
                .accessibilityAddTraits(.isHeader)
            ForEach(items, id: \.self) { value in
                HStack(alignment: .top, spacing: 9) {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(.secondary)
                        .accessibilityHidden(true)
                    Text(value).font(.subheadline).fixedSize(horizontal: false, vertical: true)
                }
                .accessibilityElement(children: .combine)
            }
        }
        .frame(maxWidth: .infinity, minHeight: 210, alignment: .topLeading)
        .padding(18)
        .background(panelBackground, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(.separator.opacity(0.55), lineWidth: 1))
    }
}

private struct HelpView: View {
    @ObservedObject var model: StatusModel
    @State private var copied = false
    private let buildIdentity = LocalReleaseBuildFile.load()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                pageHeader
                actionCard
                supportDetails
                safeSharingNotice
            }
            .frame(maxWidth: 760, alignment: .leading)
            .padding(28)
        }
        .navigationTitle("Help")
    }

    private var pageHeader: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Help & Diagnostics")
                .font(.system(.title, design: .rounded, weight: .bold))
                .accessibilityAddTraits(.isHeader)
            Text("Simple steps you can take without administrator access")
                .foregroundStyle(.secondary)
        }
    }

    private var actionCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(guidance.title).font(.headline)
            Text(guidance.explanation).foregroundStyle(.secondary)
            Text(guidance.nextStep)
            Text("The background agent checks in automatically. Refresh shows its latest result; it does not trigger a new scan or reconnect the agent.")
                .foregroundStyle(.secondary)
            HStack(spacing: 12) {
                Button { model.refresh() } label: {
                    Label("Refresh status", systemImage: "arrow.clockwise").frame(minHeight: 44)
                }
                .keyboardShortcut("r", modifiers: .command)
                .accessibilityHint("Reads the privacy-safe local status summary again")

                Button { copySupportSummary() } label: {
                    Label(copied ? "Copied" : "Copy support summary", systemImage: copied ? "checkmark" : "doc.on.doc")
                        .frame(minHeight: 44)
                }
                .accessibilityHint("Copies device, version, report time, delivery, restriction state and aggregate check counts only")
            }
            if let refreshed = model.lastRefresh {
                Text("App refreshed \(refreshed.formatted(date: .omitted, time: .standard)).")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .accessibilityLabel("Application refresh completed")
            }
        }
        .padding(20)
        .background(panelBackground, in: RoundedRectangle(cornerRadius: 16))
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(.separator.opacity(0.55), lineWidth: 1))
    }

    private var supportDetails: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Details to share with support")
                .font(.title3.weight(.semibold))
                .accessibilityAddTraits(.isHeader)
            VStack(spacing: 0) {
                FactRow(label: "Device ID", value: model.status?.deviceId ?? "Not available")
                Divider()
                FactRow(label: "Agent version", value: model.status?.agentVersion ?? "Not available")
                Divider()
                FactRow(label: "App build", value: appBuildLabel)
                Divider()
                FactRow(label: "Release channel", value: buildIdentity?.channel.label ?? "Not available")
                Divider()
                FactRow(label: "Source revision", value: buildIdentity?.sourceLabel ?? "Not available")
                Divider()
                FactRow(label: "Report time", value: formattedDate(model.status?.generatedAt))
                Divider()
                FactRow(label: "Report state", value: guidance.label)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .background(panelBackground, in: RoundedRectangle(cornerRadius: 14))
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(.separator.opacity(0.55), lineWidth: 1))
        }
    }

    private var safeSharingNotice: some View {
        Label {
            Text("Share the copied summary with your security team. Do not send keychain items, collector configuration, raw event files, terminal output containing secrets, or screenshots of organization investigations.")
                .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "exclamationmark.shield.fill").foregroundStyle(.orange)
        }
        .font(.subheadline)
        .padding(16)
        .background(.orange.opacity(0.09), in: RoundedRectangle(cornerRadius: 14))
        .accessibilityElement(children: .combine)
    }

    private func copySupportSummary() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(model.safeSupportSummary, forType: .string)
        copied = true
        NSAccessibility.post(
            element: NSApp as Any,
            notification: .announcementRequested,
            userInfo: [
                .announcement: "Privacy-safe support summary copied",
                .priority: NSAccessibilityPriorityLevel.medium.rawValue,
            ]
        )
    }

    private var guidance: ProtectionPresentation {
        .make(status: model.status, availability: model.availability, now: Date())
    }

    private var appBuildLabel: String {
        buildIdentity?.version
            ?? Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
            ?? "Not available"
    }

    private func formattedDate(_ date: Date?) -> String {
        guard let date else { return "Not available" }
        return date.formatted(date: .abbreviated, time: .standard)
    }
}

struct ContentView: View {
    @StateObject private var model: StatusModel
    @StateObject private var accountModel: AccountSetupModel
    @State private var selection: DashboardSection = .protection
    private let automaticRefresh: Bool

    @MainActor init() {
        self.init(model: StatusModel(), accountModel: AccountSetupModel(), automaticRefresh: true)
    }

    @MainActor init(model: StatusModel, accountModel: AccountSetupModel, automaticRefresh: Bool) {
        _model = StateObject(wrappedValue: model)
        _accountModel = StateObject(wrappedValue: accountModel)
        self.automaticRefresh = automaticRefresh
    }

    var body: some View {
        NavigationSplitView {
            List(DashboardSection.allCases, selection: $selection) { section in
                Label(section.label, systemImage: section.symbol)
                    .tag(section)
                    .accessibilityLabel(section.label)
            }
            .navigationTitle("ControlForge")
            .navigationSplitViewColumnWidth(min: 180, ideal: 210, max: 250)
        } detail: {
            selectedView
                .toolbar {
                    ToolbarItem(placement: .primaryAction) {
                        Button { model.refresh(); accountModel.refresh() } label: {
                            Label("Refresh status", systemImage: "arrow.clockwise")
                                .frame(minWidth: 44, minHeight: 44)
                        }
                        .help("Refresh local status (Command-R)")
                        .keyboardShortcut("r", modifiers: .command)
                        .accessibilityHint("Reads the privacy-safe local status summary again")
                    }
                }
        }
        .frame(minWidth: 760, minHeight: 600)
        .onAppear {
            if accountModel.profile != nil && accountModel.membership?.activationState != "reporting" {
                selection = .account
            }
        }
        .task {
            guard automaticRefresh else { return }
            while !Task.isCancelled {
                model.refresh()
                accountModel.refresh()
                try? await Task.sleep(nanoseconds: 30_000_000_000)
            }
        }
    }

    @ViewBuilder
    private var selectedView: some View {
        switch selection {
        case .protection: ProtectionView(model: model, accountModel: accountModel,
                                         openAccount: { selection = .account }, openHelp: { selection = .help })
        case .account: AccountOnboardingView(model: accountModel)
        case .privacy: PrivacyView()
        case .help: HelpView(model: model)
        }
    }
}

#if !CONTROLFORGE_CONTRACT_TEST
@main
struct ControlForgeUserApplication: App {
    var body: some Scene {
        WindowGroup("ControlForge") { ContentView() }
            .windowResizability(.contentMinSize)
            .commands { CommandGroup(replacing: .newItem) {} }
    }
}
#endif

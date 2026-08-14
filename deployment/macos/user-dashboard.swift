import AppKit
import Darwin
import Foundation
import SwiftUI

private let statusURL = URL(fileURLWithPath: "/Library/ControlForge/status/agent-status.json")
private let maximumStatusBytes: off_t = 65_536
private let staleStatusAge: TimeInterval = 300
private let futureClockTolerance: TimeInterval = 60
private let panelBackground = Color(nsColor: .controlBackgroundColor)

struct ControlSummary: Codable {
    let evaluated: Bool
    let total: Int
    let failed: Int
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
        } else if schemaVersion == "controlforge-agent-status-v2", let containment {
            validContainment = (containment.state == .isolated)
                == (containment.expiresAt != nil)
        } else {
            validContainment = false
        }
        let validTimestamp = generatedAt <= now.addingTimeInterval(staleStatusAge)
        return validFailure && validControls && validDelivery && validTelemetry
            && validContainment && validActions && validTimestamp
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
        guard ["controlforge-agent-status-v1", "controlforge-agent-status-v2"]
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
        let topKeys = schemaVersion == "controlforge-agent-status-v2"
            ? legacyTopKeys.union(["containment"])
            : legacyTopKeys
        let requiredTopKeys = topKeys.subtracting(["failure_stage"])
        let validContainment = schemaVersion == "controlforge-agent-status-v1"
            ? root["containment"] == nil
            : exactKeys(root["containment"], ["state", "expires_at"])
        guard Set(root.keys).isSubset(of: topKeys),
              requiredTopKeys.isSubset(of: Set(root.keys)),
              validContainment,
              exactKeys(root["controls"], ["evaluated", "total", "failed"]),
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

    func refresh() {
        do {
            let decoded = try AgentStatusDecoder.decode(LocalStatusFile.read(), now: Date())
            status = decoded
            availability = .available
            setMessage(
                decoded.runStatus == .completed
                    ? "The latest local protection summary was verified."
                    : "The latest agent run did not complete."
            )
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
        lastRefresh = Date()
    }

    var safeSupportSummary: String {
        guard let status else {
            return "ControlForge support summary\nStatus: \(message)"
        }
        return [
            "ControlForge support summary",
            "Device: \(status.deviceId)",
            "Agent version: \(status.agentVersion)",
            "Last verified: \(status.generatedAt.formatted(.iso8601))",
            "Run: \(status.runStatus.rawValue)",
            "Delivery: \(status.delivery.status.rawValue)",
            "Containment: \(status.containment?.state.rawValue ?? "not reported")",
            "Pending batches: \(pendingDescription(status.delivery))",
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
    case privacy
    case help

    var id: String { rawValue }

    var label: String {
        switch self {
        case .protection: return "Protection"
        case .privacy: return "Data & Privacy"
        case .help: return "Help"
        }
    }

    var symbol: String {
        switch self {
        case .protection: return "shield.checkered"
        case .privacy: return "hand.raised.fill"
        case .help: return "lifepreserver.fill"
        }
    }
}

private enum StatusTone {
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

private struct ProtectionPresentation {
    let label: String
    let title: String
    let explanation: String
    let nextStep: String
    let tone: StatusTone
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
    }
}

private struct ProtectionView: View {
    @ObservedObject var model: StatusModel

    private var presentation: ProtectionPresentation {
        guard let status = model.status else {
            switch model.availability {
            case .waiting:
                return ProtectionPresentation(
                    label: "Starting up",
                    title: "Protection status is not ready yet",
                    explanation: "The local agent has not published its first verified summary.",
                    nextStep: "Keep this Mac awake and connected, then refresh in a few minutes.",
                    tone: .warning
                )
            case .unsupported, .unavailable:
                return ProtectionPresentation(
                    label: "Not verified",
                    title: "Protection status needs attention",
                    explanation: model.message,
                    nextStep: "Refresh once. If this continues, contact your security team.",
                    tone: .critical
                )
            case .loading, .available:
                return ProtectionPresentation(
                    label: "Checking",
                    title: "Verifying local protection",
                    explanation: "ControlForge is reading its privacy-safe local summary.",
                    nextStep: "No action is needed while this check completes.",
                    tone: .neutral
                )
            }
        }

        let age = Date().timeIntervalSince(status.generatedAt)
        if age < -futureClockTolerance {
            return ProtectionPresentation(
                label: "Time mismatch",
                title: "This Mac's clock may be incorrect",
                explanation: "The latest summary appears to come from the future, so its age cannot be trusted.",
                nextStep: "Check Date & Time settings, then refresh this page.",
                tone: .warning
            )
        }
        if age > staleStatusAge {
            return ProtectionPresentation(
                label: "Out of date",
                title: "Protection has not checked in recently",
                explanation: "The last verified summary is older than five minutes.",
                nextStep: "Connect to the network and refresh. Contact your security team if it stays out of date.",
                tone: .warning
            )
        }
        if status.runStatus == .failed || status.delivery.status == .failed {
            return ProtectionPresentation(
                label: "Needs attention",
                title: "The latest protection run was interrupted",
                explanation: failureExplanation(status),
                nextStep: "Stay connected and refresh. If the next run also fails, contact your security team.",
                tone: .critical
            )
        }
        if !status.controls.evaluated || status.controls.total == 0 {
            return ProtectionPresentation(
                label: "Not fully verified",
                title: "Protection checks are not available",
                explanation: "The agent completed, but it did not report a usable protection-check summary.",
                nextStep: "Contact your security team if this remains after the next refresh.",
                tone: .warning
            )
        }
        if status.controls.failed > 0 || status.delivery.batchesPending > 0
            || status.telemetry.santaLinesRejected > 0 {
            return ProtectionPresentation(
                label: "Limited",
                title: "Protection is running with an issue",
                explanation: "ControlForge is active, but one or more components need review.",
                nextStep: "Keep this Mac online. Your security team can review the detailed evidence.",
                tone: .warning
            )
        }
        return ProtectionPresentation(
            label: "Protected",
            title: "ControlForge is working normally",
            explanation: "Protection checks passed and the latest summary was delivered without a backlog.",
            nextStep: "No action is needed.",
            tone: .positive
        )
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                pageHeader
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

    private var pageHeader: some View {
        HStack(alignment: .center, spacing: 16) {
            Image(systemName: "shield.checkered")
                .font(.system(size: 28, weight: .semibold))
                .foregroundStyle(.tint)
                .frame(width: 52, height: 52)
                .background(.tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 14))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text("Protection for this Mac")
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
        }
        .padding(20)
        .background(presentation.tone.color.opacity(0.08), in: RoundedRectangle(cornerRadius: 16))
        .overlay(
            RoundedRectangle(cornerRadius: 16)
                .stroke(presentation.tone.color.opacity(0.28), lineWidth: 1)
        )
        .accessibilityElement(children: .combine)
    }

    private var componentSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionHeading("Component health", subtitle: "A plain-language view of the latest local run")
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
                state: controlsState(status.controls),
                detail: controlsDetail(status.controls),
                tone: controlsTone(status.controls)
            )
            ComponentCard(
                icon: "waveform.path.ecg",
                title: "Activity collection",
                state: telemetryState(status.telemetry),
                detail: telemetryDetail(status.telemetry),
                tone: telemetryTone(status.telemetry)
            )
            ComponentCard(
                icon: "arrow.up.circle",
                title: "Secure delivery",
                state: status.delivery.status.label,
                detail: deliveryDetail(status.delivery),
                tone: deliveryTone(status.delivery)
            )
            ComponentCard(
                icon: "network.badge.shield.half.filled",
                title: "Network access",
                state: status.containment?.state.label ?? "Not reported",
                detail: containmentDetail(status.containment),
                tone: containmentTone(status.containment)
            )
        } else {
            ComponentCard(icon: "checklist", title: "Protection checks", state: "Not available", detail: "Waiting for a verified local summary.", tone: .neutral)
            ComponentCard(icon: "waveform.path.ecg", title: "Activity collection", state: "Not available", detail: "No aggregate collection quality is available yet.", tone: .neutral)
            ComponentCard(icon: "arrow.up.circle", title: "Secure delivery", state: "Not available", detail: "No delivery or backlog status is available yet.", tone: .neutral)
            ComponentCard(icon: "network.badge.shield.half.filled", title: "Network access", state: "Not available", detail: "No verified containment summary is available yet.", tone: .neutral)
        }
    }

    private var deliverySection: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionHeading("Last verified run", subtitle: "Safe operational details for support")
            VStack(spacing: 0) {
                FactRow(label: "Verified", value: formattedDate(model.status?.generatedAt))
                Divider()
                FactRow(label: "Agent version", value: model.status?.agentVersion ?? "Not available")
                Divider()
                FactRow(label: "Delivered this run", value: number(model.status?.delivery.batchesDelivered))
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
        if age < 60 { return "Verified just now" }
        if age < 3_600 { return "Verified \(Int(age / 60)) min ago" }
        if age < 86_400 { return "Verified \(Int(age / 3_600)) hr ago" }
        return "Verified \(Int(age / 86_400)) days ago"
    }

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
        if controls.failed == 0 { return "All \(controls.total) passed" }
        return "\(controls.failed) need review"
    }

    private func controlsDetail(_ controls: ControlSummary) -> String {
        guard controls.evaluated, controls.total > 0 else {
            return "The latest run did not include a usable control summary."
        }
        if controls.failed == 0 {
            return "The installed security components met every configured check."
        }
        return "Your security team can review the detailed evidence and recommended fixes."
    }

    private func controlsTone(_ controls: ControlSummary) -> StatusTone {
        guard controls.evaluated, controls.total > 0 else { return .warning }
        return controls.failed == 0 ? .positive : .warning
    }

    private func telemetryState(_ telemetry: TelemetrySummary) -> String {
        telemetry.santaLinesRejected == 0 ? "Quality verified" : "Some data rejected"
    }

    private func telemetryDetail(_ telemetry: TelemetrySummary) -> String {
        if telemetry.santaLinesRejected == 0 {
            return "\(telemetry.eventsCollected) aggregate activity items were collected in the latest run with no rejected Santa lines."
        }
        return "\(telemetry.santaLinesRejected) Santa lines could not be safely accepted in the latest run."
    }

    private func telemetryTone(_ telemetry: TelemetrySummary) -> StatusTone {
        telemetry.santaLinesRejected == 0 ? .positive : .warning
    }

    private func deliveryDetail(_ delivery: DeliverySummary) -> String {
        switch delivery.status {
        case .succeeded:
            return "The local queue is clear and the latest summary was delivered."
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
                return "Network access is restricted until automatic release by \(formattedDate(expiresAt))."
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

    private func failureExplanation(_ status: AgentStatus) -> String {
        if let stage = status.failureStage {
            return "The agent was interrupted during \(stage.label.lowercased())."
        }
        return "Secure delivery did not complete during the latest run."
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
            Text(model.message).font(.headline)
            Text("Refresh reads the existing local summary. It does not run commands, change settings, or contact the control plane directly.")
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
                .accessibilityHint("Copies device, version, run, delivery, and backlog status only")
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
                FactRow(label: "Last verified", value: formattedDate(model.status?.generatedAt))
                Divider()
                FactRow(label: "Local summary", value: model.status == nil ? "Unavailable" : "Verified")
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

    private func formattedDate(_ date: Date?) -> String {
        guard let date else { return "Not available" }
        return date.formatted(date: .abbreviated, time: .standard)
    }
}

private struct ContentView: View {
    @StateObject private var model = StatusModel()
    @State private var selection: DashboardSection = .protection

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
                        Button { model.refresh() } label: {
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
        .task {
            while !Task.isCancelled {
                model.refresh()
                try? await Task.sleep(nanoseconds: 30_000_000_000)
            }
        }
    }

    @ViewBuilder
    private var selectedView: some View {
        switch selection {
        case .protection: ProtectionView(model: model)
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

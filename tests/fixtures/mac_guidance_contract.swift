import Foundation

enum MacGuidanceFixture {
    static let scenarios = ["Reporting", "Missing", "Stopped", "Degraded", "Offline", "Backlog", "Restricted",
                            "Release overdue", "Restriction problem", "Stale", "Clock", "Legacy", "No upload", "Activity gap"]

    static func payload(_ scenario: String, now: Date = Date()) -> [String: Any] {
        var controls: [String: Any] = ["evaluated": true, "total": 3, "failed": 0, "degraded": 0, "missing": 0, "not_running": 0]
        var delivery: [String: Any] = ["status": "succeeded", "batches_delivered": 1, "batches_pending": 0, "batches_pending_is_lower_bound": false]
        var containment: [String: Any] = ["state": "not_configured", "expires_at": NSNull()]
        var date = now, failure: Any = NSNull(), schema = "controlforge-agent-status-v3"
        var telemetry = ["events_collected": 3, "santa_events_collected": 0, "santa_lines_rejected": 0]
        switch scenario {
        case "Missing": controls["failed"] = 1; controls["missing"] = 1
        case "Stopped": controls["failed"] = 1; controls["not_running"] = 1
        case "Degraded": controls["degraded"] = 1
        case "Offline": delivery["status"] = "failed"; delivery["batches_pending"] = 2
        case "Backlog": delivery["status"] = "backlogged"; delivery["batches_pending"] = 100; delivery["batches_pending_is_lower_bound"] = true
        case "Restricted", "Release overdue":
            containment = ["state": "isolated", "expires_at": ISO8601DateFormatter().string(from: now.addingTimeInterval(scenario == "Restricted" ? 300 : -30))]
        case "Restriction problem": containment["state"] = "needs_attention"
        case "Stale": date = now.addingTimeInterval(-600)
        case "Clock": date = now.addingTimeInterval(120)
        case "Legacy": schema = "controlforge-agent-status-v2"; controls = ["evaluated": true, "total": 3, "failed": 0]
        case "No upload": delivery["status"] = "not_attempted"; delivery["batches_delivered"] = 0
        case "Activity gap": telemetry["santa_lines_rejected"] = 2
        case "credential_rotation", "control_collection", "telemetry_collection", "action_polling": failure = scenario
        default: break
        }
        return ["schema_version": schema, "generated_at": ISO8601DateFormatter().string(from: date),
                "device_id": "mac-alex", "agent_version": "0.3.0", "run_status": failure is String ? "failed" : "completed",
                "failure_stage": failure, "controls": controls, "delivery": delivery, "telemetry": telemetry,
                "containment": containment, "actions_processed": 0]
    }

    static func data(_ scenario: String, now: Date = Date()) throws -> Data {
        try JSONSerialization.data(withJSONObject: payload(scenario, now: now), options: [.sortedKeys])
    }
}

@MainActor
enum MacGuidanceContractHarness {
    static func run() throws {
        let now = Date()
        let expectations = [
            "Reporting": "reporting", "Missing": "component_missing", "Stopped": "component_stopped",
            "Degraded": "component_attention", "Offline": "delivery_failed", "Backlog": "backlog",
            "Restricted": "restricted", "Release overdue": "restriction_expired",
            "Restriction problem": "restriction_attention", "Stale": "stale", "Clock": "clock",
            "Legacy": "legacy", "No upload": "not_sent", "Activity gap": "activity_gap",
            "credential_rotation": "credentials", "control_collection": "checks_interrupted",
            "telemetry_collection": "collection_interrupted", "action_polling": "team_connection",
        ]
        for (scenario, expected) in expectations {
            let status = try AgentStatusDecoder.decode(MacGuidanceFixture.data(scenario, now: now), now: now)
            let guide = ProtectionPresentation.make(status: status, availability: .available, now: now)
            guard guide.code == expected, !guide.nextStep.isEmpty else { fatalError("wrong guidance for \(scenario)") }
            if scenario != "Reporting" { guard guide.tone != .positive else { fatalError("false green \(scenario)") } }
        }
        for (availability, code) in [(SnapshotAvailability.loading, "loading"), (.waiting, "waiting"), (.unavailable, "unavailable"), (.unsupported, "unavailable")] {
            guard ProtectionPresentation.make(status: nil, availability: availability, now: now).code == code else { fatalError("empty state") }
        }
        var payload = MacGuidanceFixture.payload("Restricted", now: now)
        payload["generated_at"] = ISO8601DateFormatter().string(from: now.addingTimeInterval(-600))
        let old = try AgentStatusDecoder.decode(JSONSerialization.data(withJSONObject: payload), now: now)
        let stale = ProtectionPresentation.make(status: old, availability: .available, now: now)
        guard stale.code == "stale", stale.explanation.contains("restriction") else { fatalError("stale restriction hidden") }
        for changes: [String: Any] in [["degraded": 4], ["failed": 1, "missing": 2], ["failed": 1, "missing": 1, "not_running": 1], ["degraded": -1], ["degraded": NSNull()], ["raw_evidence": "private"]] {
            var invalid = MacGuidanceFixture.payload("Reporting", now: now)
            var controls = invalid["controls"] as! [String: Any]
            controls.merge(changes) { _, new in new }
            invalid["controls"] = controls
            do {
                _ = try AgentStatusDecoder.decode(JSONSerialization.data(withJSONObject: invalid), now: now)
                fatalError("accepted unsafe component detail")
            } catch { }
        }
        var missingDetails = MacGuidanceFixture.payload("Reporting", now: now)
        missingDetails["controls"] = ["evaluated": true, "total": 3, "failed": 0]
        do {
            _ = try AgentStatusDecoder.decode(JSONSerialization.data(withJSONObject: missingDetails), now: now)
            fatalError("v3 silently defaulted missing component counts")
        } catch { }
        var currentData = try MacGuidanceFixture.data("Reporting", now: now)
        var clock = now
        let model = StatusModel(readStatus: { currentData }, clock: { clock })
        model.refresh()
        guard model.availability == .available, model.safeSupportSummary.contains("Report state: reporting") else { fatalError("initial read") }
        clock = now.addingTimeInterval(600)
        model.refresh()
        guard model.safeSupportSummary.contains("Report state: stale") else { fatalError("stale support summary") }
        currentData = Data("not a status".utf8)
        model.refresh()
        guard model.status == nil, !model.safeSupportSummary.contains("reporting") else { fatalError("failed read retained prior success") }
        currentData = try MacGuidanceFixture.data("Degraded", now: clock)
        model.refresh()
        guard model.safeSupportSummary.contains("Security checks degraded: 1"),
              !model.safeSupportSummary.contains("password") else { fatalError("recovery failed") }
    }
}

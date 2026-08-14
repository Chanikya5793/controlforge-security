import Foundation

@main
struct UserDashboardContractHarness {
    static let now = ISO8601DateFormatter().date(from: "2026-08-22T12:00:00Z")!

    static func main() throws {
        let valid = basePayload()
        let decoded = try AgentStatusDecoder.decode(serialize(valid), now: now)
        guard decoded.deviceId == "device-test-1",
              decoded.delivery.batchesPending == 100,
              decoded.delivery.batchesPendingIsLowerBound,
              decoded.containment?.state == .isolated else {
            fatalError("valid bounded status did not decode")
        }

        var legacy = basePayload()
        legacy["schema_version"] = "controlforge-agent-status-v1"
        legacy.removeValue(forKey: "containment")
        guard try AgentStatusDecoder.decode(serialize(legacy), now: now).containment == nil else {
            fatalError("legacy status compatibility failed")
        }

        expectReject("top-level secret") { payload in
            payload["credential_secret"] = "must-never-be-visible"
        }
        expectReject("raw telemetry") { payload in
            var telemetry = payload["telemetry"] as! [String: Any]
            telemetry["raw_events"] = [["process": "/bin/private"]]
            payload["telemetry"] = telemetry
        }
        expectReject("response rationale") { payload in
            payload["response_rationale"] = "sensitive analyst reasoning"
        }
        expectReject("containment internals") { payload in
            var containment = payload["containment"] as! [String: Any]
            containment["pf_token"] = "42"
            payload["containment"] = containment
        }
        expectReject("isolated without expiry") { payload in
            var containment = payload["containment"] as! [String: Any]
            containment["expires_at"] = NSNull()
            payload["containment"] = containment
        }
        expectReject("dishonest lower bound") { payload in
            var delivery = payload["delivery"] as! [String: Any]
            delivery["batches_pending"] = 99
            payload["delivery"] = delivery
        }
        expectReject("empty backlog") { payload in
            var delivery = payload["delivery"] as! [String: Any]
            delivery["batches_pending"] = 0
            delivery["batches_pending_is_lower_bound"] = false
            payload["delivery"] = delivery
        }
        expectReject("future timestamp") { payload in
            payload["generated_at"] = "2026-08-22T12:06:00Z"
        }
        expectReject("Santa count exceeds total") { payload in
            var telemetry = payload["telemetry"] as! [String: Any]
            telemetry["santa_events_collected"] = 4
            payload["telemetry"] = telemetry
        }
    }

    static func basePayload() -> [String: Any] {
        [
            "schema_version": "controlforge-agent-status-v2",
            "generated_at": "2026-08-22T12:00:00Z",
            "device_id": "device-test-1",
            "agent_version": "0.3.0",
            "run_status": "completed",
            "failure_stage": NSNull(),
            "controls": ["evaluated": true, "total": 3, "failed": 0],
            "delivery": [
                "status": "backlogged",
                "batches_delivered": 0,
                "batches_pending": 100,
                "batches_pending_is_lower_bound": true,
            ],
            "telemetry": [
                "events_collected": 3,
                "santa_events_collected": 2,
                "santa_lines_rejected": 0,
            ],
            "containment": [
                "state": "isolated",
                "expires_at": "2026-08-22T12:15:00Z",
            ],
            "actions_processed": 0,
        ]
    }

    static func expectReject(
        _ label: String,
        mutate: (inout [String: Any]) -> Void
    ) {
        var payload = basePayload()
        mutate(&payload)
        do {
            _ = try AgentStatusDecoder.decode(serialize(payload), now: now)
            fatalError("contract accepted \(label)")
        } catch {
            return
        }
    }

    static func serialize(_ payload: [String: Any]) -> Data {
        try! JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
    }
}

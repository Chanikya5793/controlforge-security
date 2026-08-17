import Darwin
import Foundation

// Synthetic protocol fixtures only. No installed profile, Keychain, admin prompt
// or production endpoint is read or modified by this harness.
@MainActor
enum AccountOnboardingContractHarness {
    nonisolated static func data(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    nonisolated static func profileData(_ host: String = "accounts.example.com") throws -> Data {
        try data(["schema_version": "controlforge-account-server-v1", "api_host": host,
                  "api_port": 443, "device_id": "mac-alex"])
    }

    static func expectReject(_ label: String, operation: () throws -> Void) {
        do { try operation(); fatalError("accepted invalid account contract: \(label)") }
        catch { }
    }

    final class State {
        var profile = try! AccountServerProfile.decode(profileData())
        var membership: NetworkMembership?
        var unfinished = false
        var omitReceipt = false
        var privilegeCalls = 0
    }

    final class FixtureTransport: AccountTransport {
        var changed = false
        var requests: [AccountRoute] = []
        var mismatch = false
        var reject = false

        func account() -> [String: Any] {
            ["account_id": "alex", "tenant_id": "alpha", "username": "alex@alpha.example.com",
             "display_name": "Alex", "must_change_password": !changed]
        }

        func send(profile: AccountServerProfile, route: AccountRoute, body: Data?, token: String?) async throws -> Data {
            requests.append(route)
            if reject { throw AccountFlowError.unauthorized }
            let fields = try body.map { try JSONSerialization.jsonObject(with: $0) as! [String: String] }
            switch route {
            case .login, .password:
                if route == .login {
                    guard fields?["username"] == "alex@alpha.example.com", fields?["password"] != nil,
                          token == nil else { fatalError("login request contract") }
                } else {
                    guard token == String(repeating: "s", count: 43), fields?["password"] != nil else {
                        fatalError("password request contract")
                    }
                    changed = true
                }
                return try data(["token": String(repeating: "s", count: 43),
                                 "expires_at": ISO8601DateFormatter().string(from: Date().addingTimeInterval(900)),
                                 "account": account()])
            case .me:
                guard body == nil, token == String(repeating: "s", count: 43) else { fatalError("me request contract") }
                var value = account()
                value["network_name"] = "Alpha School"
                if mismatch { value["tenant_id"] = "other-network" }
                return try data(value)
            case .reset:
                guard token == nil, fields?["username"] != nil else { fatalError("reset request contract") }
                return try data(["message": "Generic reset acknowledgement"])
            case .grant:
                guard changed, token != nil, fields == ["device_id": "mac-alex"] else { fatalError("grant before setup") }
                return try data(["token": String(repeating: "g", count: 43), "device_id": "mac-alex",
                                 "expires_at": ISO8601DateFormatter().string(from: Date().addingTimeInterval(300))])
            case .logout:
                return try data(["status": "signed_out"])
            }
        }
    }

    struct FixtureBridge: AccountPrivilegeBridge {
        let state: State

        func receipt(_ activation: String) throws -> NetworkMembership {
            try NetworkMembership.decode(data([
                "schema_version": "controlforge-network-membership-v1",
                "api_host": state.profile.apiHost, "api_port": state.profile.apiPort,
                "device_id": state.profile.deviceId, "tenant_id": "alpha", "account_id": "alex",
                "network_name": "Alpha School", "local_uid": Int(getuid()),
                "enrolled_at": ISO8601DateFormatter().string(from: Date()), "activation_state": activation,
            ]), profile: state.profile)
        }

        func enroll(profile: AccountServerProfile, account: EndpointAccount, grant: EndpointGrant, name: String) async throws {
            state.privilegeCalls += 1
            guard profile == state.profile, account.accountId == "alex", account.tenantId == "alpha",
                  grant.deviceId == profile.deviceId, !account.mustChangePassword else { fatalError("bridge identity contract") }
            if !state.omitReceipt { state.membership = try receipt(state.unfinished ? "configured" : "reporting") }
            if state.unfinished { throw AccountFlowError.enrollmentUnfinished }
        }

        func finish() async throws {
            state.privilegeCalls += 1
            state.membership = try receipt("reporting")
        }
    }

    static func run() async throws {
        let profile = try AccountServerProfile.decode(profileData())
        guard try profile.url(for: .login).absoluteString == "https://accounts.example.com:443/v1/endpoint/login" else {
            fatalError("fixed HTTPS route was changed")
        }
        for host in ["https://evil.example/path", "evil.example\n", "accounts.example.com@evil.example", "127.0.0.1", "A.example"] {
            expectReject("untrusted host") { _ = try AccountServerProfile.decode(profileData(host)) }
        }
        var extra = try JSONSerialization.jsonObject(with: profileData()) as! [String: Any]
        extra["credential_secret"] = "forbidden"
        expectReject("profile secret field") { _ = try AccountServerProfile.decode(data(extra)) }
        expectReject("command injection") {
            _ = try AccountHandoffFile(url: URL(fileURLWithPath: "/unused"), uid: getuid(), digest: "x; touch /tmp/unsafe").command()
        }
        expectReject("command newline") {
            _ = try AccountHandoffFile(url: URL(fileURLWithPath: "/unused"), uid: getuid(), digest: String(repeating: "a", count: 64) + "\n").command()
        }
        try responseContracts(profile)
        try await workflowContracts()
        try fileContracts(profile)
    }

    static func responseContracts(_ profile: AccountServerProfile) throws {
        let url = try profile.url(for: .login)
        let valid = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1",
                                    headerFields: ["Content-Type": "application/json"])!
        try HTTPSAccountTransport.validate(valid, requestedURL: url, route: .login)
        for status in [201, 206, 301, 302, 307, 308, 401, 403, 429, 500] {
            let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1",
                                           headerFields: ["Content-Type": "application/json"])!
            expectReject("HTTP \(status)") { try HTTPSAccountTransport.validate(response, requestedURL: url, route: .login) }
        }
        for headers in [["Content-Type": "text/html"], ["Content-Type": "application/json", "Content-Length": "16385"]] {
            let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: headers)!
            expectReject("content contract") { try HTTPSAccountTransport.validate(response, requestedURL: url, route: .login) }
        }
        expectReject("redirected origin") {
            try HTTPSAccountTransport.validate(valid, requestedURL: URL(string: "https://other.example/v1/endpoint/login")!, route: .login)
        }
        let transport = FixtureTransport()
        var envelope: [String: Any] = ["token": String(repeating: "s", count: 43), "account": transport.account(),
                                      "expires_at": ISO8601DateFormatter().string(from: Date().addingTimeInterval(900))]
        _ = try EndpointSignIn.decode(data(envelope))
        envelope["expires_at"] = "2020-01-01T00:00:00Z"
        expectReject("expired session") { _ = try EndpointSignIn.decode(data(envelope)) }
        envelope["expires_at"] = ISO8601DateFormatter().string(from: Date().addingTimeInterval(3600))
        expectReject("unbounded session") { _ = try EndpointSignIn.decode(data(envelope)) }
        var grant: [String: Any] = ["token": String(repeating: "g", count: 43), "device_id": "different-mac",
                                   "expires_at": ISO8601DateFormatter().string(from: Date().addingTimeInterval(300))]
        expectReject("wrong device grant") { _ = try EndpointGrant.decode(data(grant), device: profile.deviceId) }
        grant["device_id"] = profile.deviceId
        grant["extra"] = "unexpected"
        expectReject("grant drift") { _ = try EndpointGrant.decode(data(grant), device: profile.deviceId) }
    }

    static func makeModel(_ state: State, _ transport: FixtureTransport) -> AccountSetupModel {
        AccountSetupModel(transport: transport, bridge: FixtureBridge(state: state),
                          readProfile: { state.profile }, readMembership: { _ in state.membership })
    }

    static func workflowContracts() async throws {
        let state = State(), transport = FixtureTransport()
        let model = makeModel(state, transport)
        await model.signIn(username: "alex@alpha.example.com", password: "initial")
        guard model.account?.mustChangePassword == true, !model.canConnect else { fatalError("initial gate") }
        await model.connect(name: "Alex’s Mac")
        guard state.privilegeCalls == 0, !transport.requests.contains(.grant) else { fatalError("bypassed initial password") }
        await model.changePassword("The river turns by the old oak!", confirmation: "different")
        guard !transport.changed else { fatalError("mismatched confirmation accepted") }
        await model.changePassword("The river turns by the old oak!", confirmation: "The river turns by the old oak!")
        guard model.canConnect, model.account?.networkName == "Alpha School" else { fatalError("setup completion") }
        state.unfinished = true
        await model.connect(name: "Alex’s Mac")
        guard model.membership?.activationState == "configured", model.canFinish, !model.canConnect else { fatalError("unfinished activation hidden") }
        await model.finish()
        guard model.membership?.activationState == "reporting", !model.canFinish,
              transport.requests.filter({ $0 == .grant }).count == 1 else { fatalError("activation reclaimed a grant") }
        await model.requestReset(username: "alex@alpha.example.com")
        guard model.notice?.contains("Nothing is sent by email") == true else { fatalError("reset expectations") }
        await model.signOut()
        guard model.account == nil, model.membership != nil, !model.busy else { fatalError("logout removed membership") }

        let changedState = State(), changedTransport = FixtureTransport()
        let changed = makeModel(changedState, changedTransport)
        await changed.signIn(username: "alex@alpha.example.com", password: "initial")
        changedState.profile = try .decode(profileData("another.example.com"))
        changed.refresh()
        guard changed.account == nil else { fatalError("session followed profile change") }

        let mismatchTransport = FixtureTransport()
        mismatchTransport.mismatch = true
        let mismatch = makeModel(State(), mismatchTransport)
        await mismatch.signIn(username: "alex@alpha.example.com", password: "initial")
        guard mismatch.account == nil, mismatch.error != nil else { fatalError("accepted changing account scope") }

        let missingState = State(), missingTransport = FixtureTransport()
        missingState.omitReceipt = true; missingTransport.changed = true
        let missing = makeModel(missingState, missingTransport)
        await missing.signIn(username: "alex@alpha.example.com", password: "already set")
        await missing.connect(name: "Alex’s Mac")
        guard missing.membership == nil, missing.error != nil else { fatalError("privilege exit alone claimed enrollment") }
        missingTransport.reject = true
        await missing.connect(name: "Alex’s Mac")
        guard missing.account == nil else { fatalError("expired session retained") }
    }

    static func fileContracts(_ profile: AccountServerProfile) throws {
        // Foundation's resolvingSymlinksInPath canonicalizes /private/var back
        // to /var on macOS. Keep the explicit non-symlink fixture path instead.
        let temporary = NSTemporaryDirectory()
        let directory = URL(fileURLWithPath: temporary.hasPrefix("/var/") ? "/private" + temporary : temporary)
            .appendingPathComponent("controlforge-account-contract-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let profileURL = directory.appendingPathComponent("profile.json")
        try profileData().write(to: profileURL)
        chmod(profileURL.path, 0o644)
        _ = try MacAccountFiles.read(profileURL, owner: getuid())
        chmod(profileURL.path, 0o666)
        expectReject("writable profile") { _ = try MacAccountFiles.read(profileURL, owner: getuid()) }
        chmod(profileURL.path, 0o644)
        let symlink = directory.appendingPathComponent("symlink.json")
        try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: profileURL)
        expectReject("symlink profile") { _ = try MacAccountFiles.read(symlink, owner: getuid()) }
        let transport = FixtureTransport(); transport.changed = true
        let account = try EndpointAccount.decode(data(transport.account()))
        let grant = EndpointGrant(token: String(repeating: "g", count: 43), deviceId: profile.deviceId,
                                  expires: Date().addingTimeInterval(300))
        let handoff = try AccountHandoffFile.create(profile: profile, account: account, grant: grant,
                                                   name: "Alex’s Mac", directory: directory)
        defer { handoff.remove() }
        let contents = try Data(contentsOf: handoff.url)
        let object = try JSONSerialization.jsonObject(with: contents) as! [String: String]
        guard Set(object.keys) == ["schema_version", "grant", "expected_account_id", "expected_tenant_id",
                                   "expected_device_id", "display_name"],
              object["grant"] == grant.token,
              !(try handoff.command()).contains(grant.token),
              handoff.url.lastPathComponent.contains(handoff.digest) else { fatalError("secret handoff contract") }
        var metadata = stat()
        guard lstat(handoff.url.path, &metadata) == 0, metadata.st_mode & 0o7777 == 0o600,
              metadata.st_uid == getuid() else { fatalError("handoff permissions") }
        expectReject("handoff overwrite") {
            _ = try AccountHandoffFile.create(profile: profile, account: account, grant: grant,
                                              name: "Alex’s Mac", directory: directory)
        }
    }
}

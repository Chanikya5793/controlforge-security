import AppKit
import CryptoKit
import Darwin
import Foundation
import SwiftUI

// Passwords, bearer sessions, grants and collector credentials are never saved
// in preferences or included in a support summary. Only the short-lived grant
// crosses the privileged boundary, in a mode-0600, digest-bound handoff file.
enum AccountFlowError: Error, Equatable {
    case invalidContract, untrustedFile, unavailable, unauthorized, limited, invalidPassword
    case authorizationCancelled, enrollmentUnfinished

    var message: String {
        switch self {
        case .invalidContract, .untrustedFile:
            return "The account setup could not be verified. Ask your admin to check this Mac’s setup."
        case .unavailable:
            return "The account server could not be reached securely. Check your connection and try again."
        case .unauthorized:
            return "Sign-in has expired or the account details were not accepted. Sign in again, or request a password reset."
        case .limited:
            return "Too many attempts. Wait 15 minutes before trying again."
        case .invalidPassword:
            return "Choose a different password with 15–128 characters. A few unrelated words work well."
        case .authorizationCancelled:
            return "Connecting was cancelled. You can try again when a Mac administrator is available."
        case .enrollmentUnfinished:
            return "This Mac hasn’t finished connecting. If “Finish connecting” is available, use it to retry. Otherwise, ask your admin to check setup."
        }
    }
}

enum AccountContract {
    static func matches(_ value: String, _ pattern: String) -> Bool {
        guard let match = value.range(of: pattern, options: .regularExpression) else { return false }
        return match == value.startIndex..<value.endIndex
    }

    static func bounded(_ value: String, _ maximum: Int) -> Bool {
        !value.isEmpty && value.unicodeScalars.count <= maximum
            && !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
    }

    static func date(_ value: String) throws -> Date {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: value) { return date }
        formatter.formatOptions = [.withInternetDateTime]
        guard let date = formatter.date(from: value) else { throw AccountFlowError.invalidContract }
        return date
    }

    static func object(_ data: Data, keys: Set<String>, optional: Set<String> = []) throws -> [String: Any] {
        guard data.count <= 16_384,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              keys.isSubset(of: Set(object.keys)),
              Set(object.keys).isSubset(of: keys.union(optional)) else {
            throw AccountFlowError.invalidContract
        }
        return object
    }

    static func decode<T: Decodable>(_ type: T.Type, data: Data) throws -> T {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        do { return try decoder.decode(type, from: data) }
        catch { throw AccountFlowError.invalidContract }
    }
}

struct AccountServerProfile: Decodable, Equatable {
    let schemaVersion: String
    let apiHost: String
    let apiPort: Int
    let deviceId: String

    static func decode(_ data: Data) throws -> Self {
        _ = try AccountContract.object(data, keys: ["schema_version", "api_host", "api_port", "device_id"])
        let profile = try AccountContract.decode(Self.self, data: data)
        guard profile.schemaVersion == "controlforge-account-server-v1",
              (4...253).contains(profile.apiHost.count), (1...65_535).contains(profile.apiPort),
              AccountContract.matches(profile.apiHost,
                "^(?:localhost|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63})$"),
              (1...128).contains(profile.deviceId.count),
              AccountContract.matches(profile.deviceId, "^[A-Za-z0-9._:-]+$") else {
            throw AccountFlowError.invalidContract
        }
        return profile
    }

    var serverLabel: String { apiPort == 443 ? apiHost : "\(apiHost):\(apiPort)" }

    func url(for route: AccountRoute) throws -> URL {
        var components = URLComponents()
        components.scheme = "https"
        components.host = apiHost
        components.port = apiPort
        components.path = route.rawValue
        guard let url = components.url else { throw AccountFlowError.invalidContract }
        return url
    }
}

struct NetworkMembership: Decodable {
    let schemaVersion: String
    let apiHost: String
    let apiPort: Int
    let deviceId: String
    let tenantId: String
    let accountId: String
    let networkName: String
    let localUid: Int
    let enrolledAt: String
    let activationState: String

    static func decode(_ data: Data, profile: AccountServerProfile) throws -> Self {
        _ = try AccountContract.object(data, keys: [
            "schema_version", "api_host", "api_port", "device_id", "tenant_id", "account_id",
            "network_name", "local_uid", "enrolled_at", "activation_state",
        ])
        let receipt = try AccountContract.decode(Self.self, data: data)
        guard receipt.schemaVersion == "controlforge-network-membership-v1",
              receipt.apiHost == profile.apiHost, receipt.apiPort == profile.apiPort,
              receipt.deviceId == profile.deviceId,
              AccountContract.bounded(receipt.tenantId, 128),
              AccountContract.bounded(receipt.accountId, 128),
              AccountContract.bounded(receipt.networkName, 120),
              (500...2_147_483_647).contains(receipt.localUid),
              ["configured", "reporting"].contains(receipt.activationState) else {
            throw AccountFlowError.invalidContract
        }
        _ = try AccountContract.date(receipt.enrolledAt)
        return receipt
    }
}

enum MacAccountFiles {
    static let profileURL = URL(fileURLWithPath: "/Library/ControlForge/status/account-server.json")
    static let receiptURL = URL(fileURLWithPath: "/Library/ControlForge/status/network-membership.json")

    static func read(_ url: URL, owner: uid_t = 0) throws -> Data {
        var parent = url.deletingLastPathComponent()
        while true {
            var metadata = stat()
            guard lstat(parent.path, &metadata) == 0,
                  metadata.st_mode & S_IFMT == S_IFDIR,
                  metadata.st_uid == 0 || metadata.st_uid == owner,
                  metadata.st_mode & 0o022 == 0 else { throw AccountFlowError.untrustedFile }
            if parent.path == "/" { break }
            parent.deleteLastPathComponent()
        }
        let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
        guard descriptor >= 0 else { throw AccountFlowError.untrustedFile }
        defer { close(descriptor) }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG, metadata.st_uid == owner,
              metadata.st_mode & 0o7777 == 0o644, metadata.st_nlink == 1,
              metadata.st_size > 0, metadata.st_size <= 4096 else { throw AccountFlowError.untrustedFile }
        var bytes = [UInt8](repeating: 0, count: 4097)
        let count = Darwin.read(descriptor, &bytes, bytes.count)
        guard count == metadata.st_size, count <= 4096 else { throw AccountFlowError.untrustedFile }
        return Data(bytes.prefix(count))
    }

    static func profile() throws -> AccountServerProfile { try .decode(read(profileURL)) }

    static func membership(profile: AccountServerProfile) throws -> NetworkMembership? {
        var metadata = stat()
        if lstat(receiptURL.path, &metadata) != 0 {
            if errno == ENOENT { return nil }
            throw AccountFlowError.untrustedFile
        }
        return try .decode(read(receiptURL), profile: profile)
    }
}

enum AccountRoute: String {
    case login = "/v1/endpoint/login"
    case me = "/v1/endpoint/me"
    case password = "/v1/endpoint/password"
    case reset = "/v1/endpoint/password-reset"
    case grant = "/v1/endpoint/enrollment-grant"
    case logout = "/v1/endpoint/logout"
}

protocol AccountTransport {
    func send(profile: AccountServerProfile, route: AccountRoute, body: Data?, token: String?) async throws -> Data
}

private final class AccountRedirectGuard: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

struct HTTPSAccountTransport: AccountTransport {
    static func validate(_ response: URLResponse, requestedURL: URL, route: AccountRoute) throws {
        let expected = route == .grant ? 201 : (route == .reset ? 202 : 200)
        guard let http = response as? HTTPURLResponse,
              http.url == requestedURL, http.statusCode == expected else {
            switch (response as? HTTPURLResponse)?.statusCode {
            case 401, 403: throw AccountFlowError.unauthorized
            case 429: throw AccountFlowError.limited
            case 400 where route == .password: throw AccountFlowError.invalidPassword
            default: throw AccountFlowError.unavailable
            }
        }
        guard http.mimeType == "application/json", response.expectedContentLength <= 16_384 else {
            throw AccountFlowError.invalidContract
        }
    }

    func send(profile: AccountServerProfile, route: AccountRoute, body: Data?, token: String?) async throws -> Data {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 20
        configuration.timeoutIntervalForResource = 20
        let session = URLSession(configuration: configuration, delegate: AccountRedirectGuard(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: try profile.url(for: route))
        request.httpMethod = route == .me ? "GET" : "POST"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.setValue("ControlForge-Account/1", forHTTPHeaderField: "User-Agent")
        if let token { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        request.httpBody = body
        do {
            let (stream, response) = try await session.bytes(for: request)
            try Self.validate(response, requestedURL: request.url!, route: route)
            var data = Data()
            for try await byte in stream {
                guard data.count < 16_384 else { throw AccountFlowError.invalidContract }
                data.append(byte)
            }
            return data
        } catch let error as AccountFlowError { throw error }
        catch { throw AccountFlowError.unavailable }
    }
}

struct EndpointAccount: Decodable {
    let accountId: String
    let username: String
    let displayName: String
    let tenantId: String
    let mustChangePassword: Bool
    let networkName: String?

    static func decode(_ data: Data, requireNetwork: Bool = false) throws -> Self {
        _ = try AccountContract.object(data, keys: [
            "account_id", "username", "display_name", "tenant_id", "must_change_password",
        ], optional: ["network_name"])
        let account = try AccountContract.decode(Self.self, data: data)
        guard AccountContract.bounded(account.accountId, 128),
              AccountContract.bounded(account.tenantId, 128),
              AccountContract.bounded(account.displayName, 120),
              AccountContract.bounded(account.username, 254),
              account.username.split(separator: "@").count == 2,
              !requireNetwork || AccountContract.bounded(account.networkName ?? "", 120) else {
            throw AccountFlowError.invalidContract
        }
        return account
    }
}

struct EndpointSignIn {
    let token: String
    let expires: Date
    let account: EndpointAccount

    static func decode(_ data: Data, now: Date = Date()) throws -> Self {
        let object = try AccountContract.object(data, keys: ["token", "expires_at", "account"])
        guard let token = object["token"] as? String,
              AccountContract.matches(token, "^[A-Za-z0-9_-]{32,128}$"),
              let expiry = object["expires_at"] as? String,
              let account = object["account"] as? [String: Any] else { throw AccountFlowError.invalidContract }
        let expires = try AccountContract.date(expiry)
        guard expires > now, expires <= now.addingTimeInterval(16 * 60) else {
            throw AccountFlowError.invalidContract
        }
        return Self(token: token, expires: expires,
                    account: try .decode(JSONSerialization.data(withJSONObject: account)))
    }
}

struct EndpointGrant {
    let token: String
    let deviceId: String
    let expires: Date

    static func decode(_ data: Data, device: String, now: Date = Date()) throws -> Self {
        let object = try AccountContract.object(data, keys: ["token", "device_id", "expires_at"])
        guard let token = object["token"] as? String,
              AccountContract.matches(token, "^[A-Za-z0-9_-]{32,128}$"),
              object["device_id"] as? String == device,
              let expiry = object["expires_at"] as? String else { throw AccountFlowError.invalidContract }
        let expires = try AccountContract.date(expiry)
        guard expires > now, expires <= now.addingTimeInterval(6 * 60) else {
            throw AccountFlowError.invalidContract
        }
        return Self(token: token, deviceId: device, expires: expires)
    }
}

struct EndpointAccountAPI {
    let profile: AccountServerProfile
    var transport: any AccountTransport = HTTPSAccountTransport()

    func request(_ route: AccountRoute, fields: [String: String]? = nil, token: String? = nil) async throws -> Data {
        let body = try fields.map { try JSONSerialization.data(withJSONObject: $0) }
        guard body == nil || body!.count <= 8192 else { throw AccountFlowError.invalidContract }
        return try await transport.send(profile: profile, route: route, body: body, token: token)
    }

    func signIn(username: String, password: String) async throws -> EndpointSignIn {
        guard (1...254).contains(username.count), (1...128).contains(password.unicodeScalars.count) else {
            throw AccountFlowError.unauthorized
        }
        return try await .decode(request(.login, fields: ["username": username, "password": password]))
    }

    func account(token: String) async throws -> EndpointAccount {
        try await .decode(request(.me, token: token), requireNetwork: true)
    }

    func password(_ password: String, token: String) async throws -> EndpointSignIn {
        guard (15...128).contains(password.unicodeScalars.count) else { throw AccountFlowError.invalidPassword }
        return try await .decode(request(.password, fields: ["password": password], token: token))
    }

    func reset(username: String) async throws {
        guard (1...254).contains(username.count) else { throw AccountFlowError.invalidContract }
        _ = try await AccountContract.object(request(.reset, fields: ["username": username]), keys: ["message"])
    }

    func grant(token: String) async throws -> EndpointGrant {
        try await .decode(request(.grant, fields: ["device_id": profile.deviceId], token: token), device: profile.deviceId)
    }

    func logout(token: String) async {
        _ = try? await request(.logout, token: token)
    }
}

struct AccountHandoffFile {
    let url: URL
    let uid: uid_t
    let digest: String

    static func create(profile: AccountServerProfile, account: EndpointAccount,
                       grant: EndpointGrant, name: String,
                       directory: URL = URL(fileURLWithPath: "/private/var/tmp")) throws -> Self {
        let uid = getuid()
        guard uid >= 500, uid <= 2_147_483_647, grant.deviceId == profile.deviceId,
              grant.expires > Date(), !account.mustChangePassword,
              AccountContract.bounded(name, 100) else { throw AccountFlowError.invalidContract }
        let data = try JSONSerialization.data(withJSONObject: [
            "schema_version": "controlforge-account-enrollment-v1", "grant": grant.token,
            "expected_account_id": account.accountId, "expected_tenant_id": account.tenantId,
            "expected_device_id": profile.deviceId, "display_name": name,
        ], options: [.sortedKeys])
        guard data.count <= 4096 else { throw AccountFlowError.invalidContract }
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        let url = directory.appendingPathComponent("controlforge-enroll-\(uid)-\(digest).json")
        let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw AccountFlowError.untrustedFile }
        var completed = false
        defer {
            close(fd)
            if !completed { unlink(url.path) }
        }
        guard fchmod(fd, 0o600) == 0 else { throw AccountFlowError.untrustedFile }
        let count = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!, data.count) }
        guard count == data.count, fsync(fd) == 0 else { throw AccountFlowError.untrustedFile }
        completed = true
        return Self(url: url, uid: uid, digest: digest)
    }

    func remove() { unlink(url.path) }

    func command() throws -> String {
        guard uid >= 500, uid <= 2_147_483_647,
              AccountContract.matches(digest, "^[a-f0-9]{64}$") else { throw AccountFlowError.invalidContract }
        return "/Library/ControlForge/bin/controlforge agent-enroll-app --request-uid \(uid) --request-sha256 \(digest)"
    }
}

protocol AccountPrivilegeBridge {
    func enroll(profile: AccountServerProfile, account: EndpointAccount, grant: EndpointGrant, name: String) async throws
    func finish() async throws
}

struct MacAccountPrivilegeBridge: AccountPrivilegeBridge {
    func enroll(profile: AccountServerProfile, account: EndpointAccount, grant: EndpointGrant, name: String) async throws {
        let file = try AccountHandoffFile.create(profile: profile, account: account, grant: grant, name: name)
        defer { file.remove() }
        try await authorize(file.command())
    }

    func finish() async throws {
        let uid = getuid()
        guard uid >= 500, uid <= 2_147_483_647 else { throw AccountFlowError.invalidContract }
        try await authorize("/Library/ControlForge/bin/controlforge agent-finish-account-enrollment --request-uid \(uid)")
    }

    private func authorize(_ command: String) async throws {
        // Only fixed command words, a numeric UID and a locally computed hex hash
        // can enter this AppleScript. No account, password, path or server input.
        try await Task.detached(priority: .userInitiated) {
            let source = "do shell script \"\(command)\" with administrator privileges"
            guard let script = NSAppleScript(source: source) else { throw AccountFlowError.enrollmentUnfinished }
            var error: NSDictionary?
            _ = script.executeAndReturnError(&error)
            if let error {
                if error[NSAppleScript.errorNumber] as? Int == -128 { throw AccountFlowError.authorizationCancelled }
                // Never show raw script/CLI output: it is outside the UI contract.
                throw AccountFlowError.enrollmentUnfinished
            }
        }.value
    }
}

@MainActor
final class AccountSetupModel: ObservableObject {
    @Published private(set) var profile: AccountServerProfile?
    @Published private(set) var membership: NetworkMembership?
    @Published private(set) var account: EndpointAccount?
    @Published private(set) var busy = false
    @Published private(set) var error: String?
    @Published private(set) var notice: String?
    @Published private(set) var membershipUnverified = false
    private var session: EndpointSignIn?
    private let transport: any AccountTransport
    private let bridge: any AccountPrivilegeBridge
    private let readProfile: () throws -> AccountServerProfile
    private let readMembership: (AccountServerProfile) throws -> NetworkMembership?

    init(transport: any AccountTransport = HTTPSAccountTransport(),
         bridge: any AccountPrivilegeBridge = MacAccountPrivilegeBridge(),
         readProfile: @escaping () throws -> AccountServerProfile = MacAccountFiles.profile,
         readMembership: @escaping (AccountServerProfile) throws -> NetworkMembership? = MacAccountFiles.membership) {
        self.transport = transport
        self.bridge = bridge
        self.readProfile = readProfile
        self.readMembership = readMembership
        refresh()
    }

    var canConnect: Bool { account != nil && account?.mustChangePassword == false && membership == nil && !membershipUnverified }
    var canFinish: Bool { membership?.activationState == "configured" && membership?.localUid == Int(getuid()) }

    func refresh() {
        guard !busy else { return }
        refreshFiles()
        if let session, session.expires <= Date() {
            self.session = nil
            account = nil
            notice = "Your account session expired. Device reporting is unchanged."
        }
    }

    private func refreshFiles() {
        do {
            let latest = try readProfile()
            if latest != profile { session = nil; account = nil }
            profile = latest
            do {
                membership = try readMembership(latest)
                membershipUnverified = false
            } catch {
                membership = nil
                membershipUnverified = true
                self.error = AccountFlowError.untrustedFile.message
            }
        } catch {
            profile = nil; membership = nil; session = nil; account = nil
            membershipUnverified = true
        }
    }

    private func api() throws -> EndpointAccountAPI {
        guard let profile else { throw AccountFlowError.untrustedFile }
        return EndpointAccountAPI(profile: profile, transport: transport)
    }

    private func activeToken() throws -> String {
        guard let session, session.expires > Date() else { throw AccountFlowError.unauthorized }
        return session.token
    }

    private func install(_ issue: EndpointSignIn, api: EndpointAccountAPI) async throws {
        let current = try await api.account(token: issue.token)
        guard current.accountId == issue.account.accountId, current.tenantId == issue.account.tenantId,
              current.username == issue.account.username,
              current.mustChangePassword == issue.account.mustChangePassword else { throw AccountFlowError.invalidContract }
        session = issue
        account = current
    }

    private func run(_ operation: () async throws -> Void) async {
        guard !busy else { return }
        busy = true; error = nil; notice = nil
        defer { busy = false }
        do { try await operation() }
        catch {
            let failure = error as? AccountFlowError ?? .unavailable
            if failure == .unauthorized { session = nil; account = nil }
            self.error = failure.message
        }
    }

    func signIn(username: String, password: String) async {
        await run {
            let api = try self.api()
            let issue = try await api.signIn(username: username.trimmingCharacters(in: .whitespacesAndNewlines), password: password)
            try await self.install(issue, api: api)
        }
    }

    func changePassword(_ password: String, confirmation: String) async {
        guard password == confirmation else { error = "The passwords don’t match. Enter the same password in both fields."; return }
        await run {
            guard self.account?.mustChangePassword == true else { throw AccountFlowError.unauthorized }
            let api = try self.api()
            let issue = try await api.password(password, token: self.activeToken())
            try await self.install(issue, api: api)
            self.notice = "Your password is set. Now connect this Mac to your network."
        }
    }

    func requestReset(username: String) async {
        await run {
            try await self.api().reset(username: username.trimmingCharacters(in: .whitespacesAndNewlines))
            self.notice = "If this account is active, your admin will see a reset request. Contact them to verify your identity and receive a new password. Nothing is sent by email."
        }
    }

    func signOut() async {
        await run {
            let token = self.session?.token
            self.session = nil; self.account = nil
            if let token, let api = try? self.api() { await api.logout(token: token) }
            self.notice = "You’re signed out. This Mac’s device reporting is unchanged."
        }
    }

    func connect(name: String) async {
        await run {
            let previousProfile = self.profile
            self.refreshFiles()
            guard previousProfile == self.profile, self.canConnect,
                  let profile = self.profile, let account = self.account else { throw AccountFlowError.untrustedFile }
            let grant = try await self.api().grant(token: self.activeToken())
            do { try await self.bridge.enroll(profile: profile, account: account, grant: grant, name: name.trimmingCharacters(in: .whitespacesAndNewlines)) }
            catch { self.refreshFiles(); throw error }
            self.refreshFiles()
            guard let membership = self.membership, membership.activationState == "reporting",
                  membership.accountId == account.accountId, membership.tenantId == account.tenantId,
                  membership.localUid == Int(getuid()) else { throw AccountFlowError.enrollmentUnfinished }
            self.notice = "This Mac connected and completed its first check-in. Open Protection for its latest status."
        }
    }

    func finish() async {
        await run {
            self.refreshFiles()
            guard self.canFinish else { throw AccountFlowError.untrustedFile }
            do { try await self.bridge.finish() }
            catch { self.refreshFiles(); throw error }
            self.refreshFiles()
            guard self.membership?.activationState == "reporting" else { throw AccountFlowError.enrollmentUnfinished }
            self.notice = "The first check-in completed. Open Protection for this Mac’s latest status."
        }
    }
}

struct AccountOnboardingView: View {
    @ObservedObject var model: AccountSetupModel
    @State private var username = ""
    @State private var password = ""
    @State private var confirmation = ""
    @State private var deviceName = Host.current().localizedName ?? "My Mac"
    @State private var requestingReset = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                Label("Your network", systemImage: "person.crop.circle.badge.checkmark")
                    .font(.system(size: 28, weight: .bold))
                    .accessibilityAddTraits(.isHeader)
                Text("Connect this Mac to the people who look after it.")
                    .font(.title3).foregroundStyle(.secondary)
                if let profile = model.profile {
                    Label("Account server: \(profile.serverLabel)", systemImage: "lock.shield")
                        .font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                    if let membership = model.membership { membershipCard(membership) }
                    if let error = model.error { message(error, symbol: "exclamationmark.triangle", color: .orange) }
                    if let notice = model.notice { message(notice, symbol: "info.circle", color: .secondary) }
                    if model.busy {
                        HStack(spacing: 12) {
                            ProgressView().controlSize(.small)
                            Text("Working… If macOS asks for an administrator, finish that prompt to continue.")
                        }.accessibilityElement(children: .combine)
                    }
                    if requestingReset { resetCard }
                    else if let account = model.account {
                        if account.mustChangePassword { firstPasswordCard(account) }
                        else { connectedAccountCard(account) }
                    } else { signInCard }
                } else {
                    card {
                        Text("Account sign-in isn’t set up yet").font(.title2.bold()).accessibilityAddTraits(.isHeader)
                        Text("Ask your network admin to configure this Mac’s account server. You don’t need to enter a server address or make an account yourself.")
                        Text("Existing device reporting, if configured, is unchanged.").foregroundStyle(.secondary)
                        Button("Check setup again") { model.refresh() }.controlSize(.large)
                    }
                }
                Text("Your network username looks like an email address, but it is only a sign-in name. Password resets are handled by your admin—not by email.")
                    .font(.callout).foregroundStyle(.secondary)
            }.frame(maxWidth: 680, alignment: .leading).padding(32)
        }
        .onChange(of: model.account?.accountId) { _ in password = ""; confirmation = "" }
        .onDisappear { password = ""; confirmation = "" }
        .navigationTitle("Account")
    }

    private var signInCard: some View {
        card {
            Text(model.membership == nil ? "1 · Sign in to your network" : "Sign in for account tools").font(.title2.bold()).accessibilityAddTraits(.isHeader)
            Text(model.membership == nil
                 ? "Use the username and initial password your admin gave you."
                 : "Device reporting does not require you to stay signed in here. Sign in to check your account details, or request a password reset below.")
            field("Network username") {
                TextField("Your admin-provided username", text: $username).textContentType(.username)
            }
            field("Password") { SecureField("Password", text: $password).textContentType(.password) }
            Button("Sign in") {
                let supplied = password
                password = ""
                Task { await model.signIn(username: username, password: supplied) }
            }.buttonStyle(.borderedProminent).controlSize(.large)
                .disabled(model.busy || username.isEmpty || password.isEmpty)
            Button("Forgot your password?") { password = ""; requestingReset = true }.disabled(model.busy)
        }
    }

    private func firstPasswordCard(_ account: EndpointAccount) -> some View {
        card {
            Text("2 · Choose your password").font(.title2.bold()).accessibilityAddTraits(.isHeader)
            Text("Hi \(account.displayName). Replace the initial password from your admin before connecting this Mac.")
            field("New password") { newPasswordField("15–128 characters", text: $password) }
            field("Confirm new password") { newPasswordField("Enter it again", text: $confirmation) }
            Text("Try a few unrelated words. Keep this password to yourself.").font(.callout).foregroundStyle(.secondary)
            Button("Set my password") {
                let supplied = password, repeated = confirmation
                password = ""; confirmation = ""
                Task { await model.changePassword(supplied, confirmation: repeated) }
            }.buttonStyle(.borderedProminent).controlSize(.large)
                .disabled(model.busy || password.isEmpty || confirmation.isEmpty)
            Button("Sign out") { Task { await model.signOut() } }.disabled(model.busy)
        }
    }

    private func connectedAccountCard(_ account: EndpointAccount) -> some View {
        card {
            Text(model.membership == nil ? "3 · Connect this Mac" : "Your account").font(.title2.bold()).accessibilityAddTraits(.isHeader)
            Text(account.displayName).font(.headline)
            Text(account.username).textSelection(.enabled)
            Text(account.networkName ?? "Your network").foregroundStyle(.secondary)
            if model.canConnect {
                field("Name for this Mac") { TextField("For example, Alex’s MacBook", text: $deviceName) }
                Text("Your admin will see this device and its security status. macOS will ask an administrator to approve setup. Signing in alone does not connect the device.")
                Button("Connect this Mac") { Task { await model.connect(name: deviceName) } }
                    .buttonStyle(.borderedProminent).controlSize(.large)
                    .disabled(model.busy || !AccountContract.bounded(deviceName, 100))
            } else if let membership = model.membership, membership.accountId != account.accountId {
                Text("This Mac is already connected through another account. Ask your admin about moving it; signing in does not change its network.")
            }
            HStack {
                Button("Request a password reset") { username = account.username; requestingReset = true }
                Button("Sign out") { Task { await model.signOut() } }
            }.disabled(model.busy)
        }
    }

    private var resetCard: some View {
        card {
            Text("Ask your admin for a reset").font(.title2.bold()).accessibilityAddTraits(.isHeader)
            Text("We’ll add a request to your network admin’s dashboard. Contact them directly to verify who you are and get your new password.")
            field("Network username") { TextField("Your admin-provided username", text: $username).textContentType(.username) }
            Button("Request password reset") { Task { await model.requestReset(username: username) } }
                .buttonStyle(.borderedProminent).controlSize(.large).disabled(model.busy || username.isEmpty)
            Button("Back to account") { requestingReset = false }.disabled(model.busy)
        }
    }

    private func membershipCard(_ membership: NetworkMembership) -> some View {
        card {
            Label(membership.activationState == "reporting" ? "Mac connected" : "Finish connecting this Mac",
                  systemImage: membership.activationState == "reporting" ? "checkmark.circle" : "clock")
                .font(.title2.bold())
                .accessibilityAddTraits(.isHeader)
            Text(membership.networkName).font(.headline)
            if membership.activationState == "reporting" {
                Text("Setup completed its first check-in. Open Protection for the latest connection and security status; this setup record is not a live health check.")
            } else {
                Text("Device credentials are installed, but setup has not verified the first check-in. No new enrollment code is needed.")
                if model.canFinish {
                    Button("Finish connecting") { Task { await model.finish() } }
                        .buttonStyle(.borderedProminent).controlSize(.large).disabled(model.busy)
                } else {
                    Text("Ask the Mac user who started setup, or your admin, to finish connecting.")
                }
            }
            Button("Refresh account status") { model.refresh() }.disabled(model.busy)
        }
    }

    private func message(_ text: String, symbol: String, color: Color) -> some View {
        Label(text, systemImage: symbol).foregroundStyle(color).fixedSize(horizontal: false, vertical: true)
            .accessibilityElement(children: .combine)
    }

    private func field<Content: View>(_ label: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(.headline)
            content().textFieldStyle(.roundedBorder).controlSize(.large).accessibilityLabel(label)
        }.disabled(model.busy)
    }

    @ViewBuilder
    private func newPasswordField(_ placeholder: String, text: Binding<String>) -> some View {
        if #available(macOS 14, *) {
            SecureField(placeholder, text: text).textContentType(.newPassword)
        } else {
            SecureField(placeholder, text: text)
        }
    }

    private func card<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 16, content: content)
            .frame(maxWidth: .infinity, alignment: .leading).padding(24)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 16))
            .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.secondary.opacity(0.15)))
    }
}

import Darwin
import Foundation
import Security

let runtime = "/Library/ControlForge/bin/controlforge-runtime"
let requiredAccounts = [
    "credential-id",
    "credential-secret",
]
let accessAccounts = [
    "access-client-id",
    "access-client-secret",
]
let credentialPairAccount = "credential-pair-v1"
let allowedAccounts = Set(requiredAccounts + accessAccounts + [credentialPairAccount])

let keychainService = "com.controlforge.collector.v2"

func openSystemKeychain() -> SecKeychain {
    var keychain: SecKeychain?
    let status = SecKeychainOpen("/Library/Keychains/System.keychain", &keychain)
    guard status == errSecSuccess, let keychain else {
        exit(70)
    }
    return keychain
}

func findKeychainAccount(_ account: String, required: Bool) -> Data? {
    guard geteuid() == 0, allowedAccounts.contains(account) else {
        exit(77)
    }

    let keychain = openSystemKeychain()
    var passwordLength: UInt32 = 0
    var passwordData: UnsafeMutableRawPointer?
    let findStatus = keychainService.withCString { servicePointer in
        account.withCString { accountPointer in
            SecKeychainFindGenericPassword(
                keychain,
                UInt32(keychainService.utf8.count), servicePointer,
                UInt32(account.utf8.count), accountPointer,
                &passwordLength, &passwordData, nil
            )
        }
    }
    if findStatus == errSecItemNotFound && !required {
        return nil
    }
    guard findStatus == errSecSuccess, let passwordData, passwordLength > 0 else {
        exit(71)
    }
    defer {
        SecKeychainItemFreeContent(nil, passwordData)
    }
    return Data(bytes: passwordData, count: Int(passwordLength))
}

func readKeychainAccount(_ account: String) -> Data {
    guard let value = findKeychainAccount(account, required: true) else {
        exit(71)
    }
    return value
}

func findKeychainItem(_ keychain: SecKeychain, account: String) -> (OSStatus, SecKeychainItem?) {
    var item: SecKeychainItem?
    let status = keychainService.withCString { servicePointer in
        account.withCString { accountPointer in
            SecKeychainFindGenericPassword(
                keychain,
                UInt32(keychainService.utf8.count), servicePointer,
                UInt32(account.utf8.count), accountPointer,
                nil, nil, &item
            )
        }
    }
    return (status, item)
}

func addKeychainAccount(
    _ keychain: SecKeychain,
    account: String,
    value: Data
) -> (OSStatus, SecKeychainItem?) {
    var item: SecKeychainItem?
    let status = value.withUnsafeBytes { valuePointer in
        keychainService.withCString { servicePointer in
            account.withCString { accountPointer in
                SecKeychainAddGenericPassword(
                    keychain,
                    UInt32(keychainService.utf8.count), servicePointer,
                    UInt32(account.utf8.count), accountPointer,
                    UInt32(value.count), valuePointer.baseAddress!,
                    &item
                )
            }
        }
    }
    return (status, item)
}

func effectiveCredentialPair() -> [String: Data] {
    if let pairData = findKeychainAccount(credentialPairAccount, required: false) {
        guard pairData.count <= 4096,
              let object = try? JSONSerialization.jsonObject(with: pairData),
              let values = object as? [String: String],
              Set(values.keys) == Set(requiredAccounts),
              let credentialID = values["credential-id"], !credentialID.isEmpty,
              let credentialSecret = values["credential-secret"], !credentialSecret.isEmpty else {
            exit(75)
        }
        return [
            "credential-id": Data(credentialID.utf8),
            "credential-secret": Data(credentialSecret.utf8),
        ]
    }
    return [
        "credential-id": readKeychainAccount("credential-id"),
        "credential-secret": readKeychainAccount("credential-secret"),
    ]
}

func replaceCredentialPair() -> Never {
    guard geteuid() == 0 else {
        exit(77)
    }
    var input = FileHandle.standardInput.readData(ofLength: 4097)
    defer {
        input.resetBytes(in: 0..<input.count)
    }
    let expectedKeys = Set(["expected-credential-id", "credential-id", "credential-secret"])
    guard input.count <= 4096,
          let object = try? JSONSerialization.jsonObject(with: input),
          let values = object as? [String: String],
          Set(values.keys) == expectedKeys,
          let expectedID = values["expected-credential-id"], !expectedID.isEmpty,
          let credentialID = values["credential-id"], !credentialID.isEmpty,
          let credentialSecret = values["credential-secret"], !credentialSecret.isEmpty,
          let currentIDData = effectiveCredentialPair()["credential-id"],
          String(data: currentIDData, encoding: .utf8) == expectedID else {
        exit(73)
    }
    guard let replacement = try? JSONSerialization.data(
        withJSONObject: [
            "credential-id": credentialID,
            "credential-secret": credentialSecret,
        ],
        options: [.sortedKeys]
    ) else {
        exit(65)
    }
    var replacementData = replacement
    defer {
        replacementData.resetBytes(in: 0..<replacementData.count)
    }
    let keychain = openSystemKeychain()
    let (findStatus, existingItem) = findKeychainItem(keychain, account: credentialPairAccount)
    if findStatus == errSecItemNotFound {
        let (addStatus, _) = addKeychainAccount(
            keychain,
            account: credentialPairAccount,
            value: replacementData
        )
        exit(addStatus == errSecSuccess ? 0 : 74)
    }
    guard findStatus == errSecSuccess, let existingItem else {
        exit(74)
    }
    let updateStatus = replacementData.withUnsafeBytes { pointer in
        SecKeychainItemModifyAttributesAndData(
            existingItem,
            nil,
            UInt32(replacementData.count),
            pointer.baseAddress
        )
    }
    exit(updateStatus == errSecSuccess ? 0 : 74)
}

func importCredentialPair() -> Never {
    guard geteuid() == 0 else {
        exit(77)
    }
    var input = FileHandle.standardInput.readData(ofLength: 4097)
    defer {
        input.resetBytes(in: 0..<input.count)
    }
    guard input.count <= 4096,
          let object = try? JSONSerialization.jsonObject(with: input),
          let values = object as? [String: String],
          Set(values.keys) == Set(requiredAccounts),
          let credentialID = values["credential-id"], !credentialID.isEmpty,
          let credentialSecret = values["credential-secret"], !credentialSecret.isEmpty else {
        exit(65)
    }

    let keychain = openSystemKeychain()
    for account in requiredAccounts {
        let (status, _) = findKeychainItem(keychain, account: account)
        guard status == errSecItemNotFound else {
            exit(73)
        }
    }

    var credentialIDData = Data(credentialID.utf8)
    var credentialSecretData = Data(credentialSecret.utf8)
    defer {
        credentialIDData.resetBytes(in: 0..<credentialIDData.count)
        credentialSecretData.resetBytes(in: 0..<credentialSecretData.count)
    }
    let (idStatus, idItem) = addKeychainAccount(
        keychain,
        account: "credential-id",
        value: credentialIDData
    )
    guard idStatus == errSecSuccess, let idItem else {
        exit(74)
    }
    let (secretStatus, secretItem) = addKeychainAccount(
        keychain,
        account: "credential-secret",
        value: credentialSecretData
    )
    guard secretStatus == errSecSuccess, secretItem != nil else {
        SecKeychainItemDelete(idItem)
        exit(74)
    }
    exit(0)
}

func requireCredentialPairEmpty() -> Never {
    guard geteuid() == 0 else {
        exit(77)
    }
    let keychain = openSystemKeychain()
    for account in requiredAccounts + [credentialPairAccount] {
        let (status, _) = findKeychainItem(keychain, account: account)
        guard status == errSecItemNotFound else {
            exit(73)
        }
    }
    exit(0)
}

func reportEnrollmentState() -> Never {
    guard geteuid() == 0 else {
        exit(77)
    }
    let keychain = openSystemKeychain()
    var present = false
    for account in allowedAccounts.sorted() {
        // Metadata lookup only: findKeychainItem supplies nil password outputs.
        let (status, _) = findKeychainItem(keychain, account: account)
        if status == errSecSuccess {
            present = true
        } else if status != errSecItemNotFound {
            exit(74)
        }
    }
    print(present ? "present" : "empty")
    exit(0)
}

func deleteAllKeychainAccounts() -> Never {
    guard geteuid() == 0 else {
        exit(77)
    }
    let keychain = openSystemKeychain()
    for account in allowedAccounts.sorted() {
        let (status, item) = findKeychainItem(keychain, account: account)
        if status == errSecItemNotFound {
            continue
        }
        guard status == errSecSuccess, let item else {
            exit(74)
        }
        guard SecKeychainItemDelete(item) == errSecSuccess else {
            exit(74)
        }
    }
    exit(0)
}

func importKeychainAccount(_ account: String) -> Never {
    guard geteuid() == 0, allowedAccounts.contains(account) else {
        exit(77)
    }

    var secret = FileHandle.standardInput.readDataToEndOfFile()
    while secret.last == 10 || secret.last == 13 {
        secret.removeLast()
    }
    guard !secret.isEmpty else {
        exit(65)
    }

    let keychain = openSystemKeychain()
    var existingItem: SecKeychainItem?
    let findStatus = keychainService.withCString { servicePointer in
        account.withCString { accountPointer in
            SecKeychainFindGenericPassword(
                keychain,
                UInt32(keychainService.utf8.count), servicePointer,
                UInt32(account.utf8.count), accountPointer,
                nil, nil, &existingItem
            )
        }
    }
    guard findStatus == errSecItemNotFound else {
        exit(73)
    }

    let addStatus = secret.withUnsafeBytes { secretPointer in
        keychainService.withCString { servicePointer in
            account.withCString { accountPointer in
                SecKeychainAddGenericPassword(
                    keychain,
                    UInt32(keychainService.utf8.count), servicePointer,
                    UInt32(account.utf8.count), accountPointer,
                    UInt32(secret.count), secretPointer.baseAddress!,
                    nil
                )
            }
        }
    }
    secret.resetBytes(in: 0..<secret.count)
    exit(addStatus == errSecSuccess ? 0 : 74)
}

let arguments = Array(CommandLine.arguments.dropFirst())
if arguments.first == "keychain-read" {
    guard arguments.count == 2 else {
        exit(64)
    }
    if requiredAccounts.contains(arguments[1]) {
        guard let value = effectiveCredentialPair()[arguments[1]] else {
            exit(71)
        }
        FileHandle.standardOutput.write(value)
    } else {
        FileHandle.standardOutput.write(readKeychainAccount(arguments[1]))
    }
    exit(0)
}
if arguments.first == "keychain-import" {
    guard arguments.count == 2 else {
        exit(64)
    }
    importKeychainAccount(arguments[1])
}
if arguments.first == "keychain-import-pair" {
    guard arguments.count == 1 else {
        exit(64)
    }
    importCredentialPair()
}
if arguments.first == "keychain-replace-pair" {
    guard arguments.count == 1 else {
        exit(64)
    }
    replaceCredentialPair()
}
if arguments.first == "keychain-require-empty" {
    guard arguments.count == 1 else {
        exit(64)
    }
    requireCredentialPairEmpty()
}
if arguments.first == "keychain-enrollment-state" {
    guard arguments.count == 1 else {
        exit(64)
    }
    reportEnrollmentState()
}
if arguments.first == "keychain-delete-all" {
    guard arguments.count == 1 else {
        exit(64)
    }
    deleteAllKeychainAccounts()
}

let child = Process()
child.executableURL = URL(fileURLWithPath: runtime)
var childArguments = arguments
var credentialPayload: Data?
var credentialPipe: Pipe?
if arguments.first == "agent" {
    var credentials: [String: String] = [:]
    let effectiveCredentials = effectiveCredentialPair()
    for account in requiredAccounts {
        guard let data = effectiveCredentials[account],
              let value = String(data: data, encoding: .utf8) else {
            exit(75)
        }
        credentials[account] = value
    }
    let accessID = findKeychainAccount("access-client-id", required: false)
    let accessSecret = findKeychainAccount("access-client-secret", required: false)
    guard (accessID == nil) == (accessSecret == nil) else {
        exit(78)
    }
    if let accessID, let accessSecret {
        guard let clientID = String(data: accessID, encoding: .utf8),
              let clientSecret = String(data: accessSecret, encoding: .utf8) else {
            exit(75)
        }
        credentials["access-client-id"] = clientID
        credentials["access-client-secret"] = clientSecret
    }
    guard let payload = try? JSONSerialization.data(withJSONObject: credentials) else {
        exit(76)
    }
    credentialPayload = payload
    let pipe = Pipe()
    credentialPipe = pipe
    child.standardInput = pipe
    childArguments.append("--credential-json-stdin")
} else {
    child.standardInput = FileHandle.standardInput
}
child.arguments = childArguments
child.standardOutput = FileHandle.standardOutput
child.standardError = FileHandle.standardError
do {
    try child.run()
    if var payload = credentialPayload, let pipe = credentialPipe {
        pipe.fileHandleForWriting.write(payload)
        try? pipe.fileHandleForWriting.close()
        payload.resetBytes(in: 0..<payload.count)
        credentialPayload = nil
    }
    child.waitUntilExit()
    exit(child.terminationStatus)
} catch {
    exit(72)
}

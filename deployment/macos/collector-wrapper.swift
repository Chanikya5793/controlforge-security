import Darwin
import Foundation
import Security

let runtime = "/Library/ControlForge/bin/controlforge-runtime"
let allowedAccounts: Set<String> = [
    "credential-id",
    "credential-secret",
    "access-client-id",
    "access-client-secret",
]

let keychainService = "com.controlforge.collector.v2"

func openSystemKeychain() -> SecKeychain {
    var keychain: SecKeychain?
    let status = SecKeychainOpen("/Library/Keychains/System.keychain", &keychain)
    guard status == errSecSuccess, let keychain else {
        exit(70)
    }
    return keychain
}

func readKeychainAccount(_ account: String) -> Data {
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
    guard findStatus == errSecSuccess, let passwordData, passwordLength > 0 else {
        exit(71)
    }
    defer {
        SecKeychainItemFreeContent(nil, passwordData)
    }
    return Data(bytes: passwordData, count: Int(passwordLength))
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
    FileHandle.standardOutput.write(readKeychainAccount(arguments[1]))
    exit(0)
}
if arguments.first == "keychain-import" {
    guard arguments.count == 2 else {
        exit(64)
    }
    importKeychainAccount(arguments[1])
}

let child = Process()
child.executableURL = URL(fileURLWithPath: runtime)
var childArguments = arguments
var credentialPayload: Data?
var credentialPipe: Pipe?
if arguments.first == "agent" {
    var credentials: [String: String] = [:]
    for account in allowedAccounts {
        guard let value = String(data: readKeychainAccount(account), encoding: .utf8) else {
            exit(75)
        }
        credentials[account] = value
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

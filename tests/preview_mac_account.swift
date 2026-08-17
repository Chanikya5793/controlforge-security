// Developer-only visual fixture. Never compiled into the shipped application.
import SwiftUI

@MainActor
final class SyntheticAccountPreview: ObservableObject {
    @Published var model = AccountSetupModel(
        readProfile: { throw AccountFlowError.untrustedFile }, readMembership: { _ in nil }
    )

    func show(_ stage: String) async {
        typealias Fixture = AccountOnboardingContractHarness
        let state = Fixture.State(), transport = Fixture.FixtureTransport()
        if stage == "Connect" || stage == "Pending" || stage == "Complete" { transport.changed = true }
        let next = Fixture.makeModel(state, transport)
        if stage != "Sign-in" {
            await next.signIn(username: "alex@alpha.example.com", password: "Synthetic test password")
        }
        if stage == "Pending" || stage == "Complete" {
            state.unfinished = stage == "Pending"
            await next.connect(name: "Synthetic Mac")
        }
        model = next
    }
}

struct SyntheticAccountPreviewView: View {
    @StateObject private var preview = SyntheticAccountPreview()
    @State private var stage = "Sign-in"

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 10) {
                Text("UI PREVIEW · Synthetic local account · No server or administrator prompt")
                    .font(.caption.bold()).foregroundStyle(.orange)
                Picker("Preview stage", selection: $stage) {
                    ForEach(["Sign-in", "First password", "Connect", "Pending", "Complete"], id: \.self) {
                        Text($0).tag($0)
                    }
                }.pickerStyle(.segmented)
            }.padding()
            Divider()
            AccountOnboardingView(model: preview.model)
        }
        .frame(width: 800, height: 820)
        .task(id: stage) { await preview.show(stage) }
    }
}

@main
struct SyntheticAccountPreviewApp: App {
    var body: some Scene {
        WindowGroup("ControlForge Account · Synthetic Preview") { SyntheticAccountPreviewView() }
            .windowResizability(.contentSize)
    }
}

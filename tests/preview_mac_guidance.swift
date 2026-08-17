// Developer-only native preview. All state is synthetic; no installed files or server are used.
import SwiftUI

@MainActor
struct GuidancePreviewScreen: View {
    let model: StatusModel
    let accounts: AccountSetupModel

    init(scenario: String) {
        model = StatusModel(readStatus: { try MacGuidanceFixture.data(scenario) })
        model.refresh()
        let state = AccountOnboardingContractHarness.State()
        state.membership = try! AccountOnboardingContractHarness.FixtureBridge(state: state).receipt("reporting")
        accounts = AccountOnboardingContractHarness.makeModel(state, .init())
    }

    var body: some View {
        ContentView(model: model, accountModel: accounts, automaticRefresh: false)
    }
}

struct GuidancePreviewView: View {
    @State private var scenario = "Reporting"
    var body: some View {
        GuidancePreviewScreen(scenario: scenario).id(scenario)
            .safeAreaInset(edge: .bottom) {
                Text("SYNTHETIC PREVIEW · No live device or server")
                    .font(.caption.bold()).foregroundStyle(.orange).padding(8)
                    .frame(maxWidth: .infinity).background(.background)
            }
            .toolbar {
                ToolbarItem {
                Picker("Report scenario", selection: $scenario) {
                    ForEach(MacGuidanceFixture.scenarios, id: \.self) { Text($0).tag($0) }
                }.frame(width: 230)
                }
            }
            .frame(width: 760, height: 600)
    }
}

@main
struct GuidancePreviewApp: App {
    var body: some Scene {
        WindowGroup("ControlForge Guidance · Synthetic Preview") { GuidancePreviewView() }
            .defaultSize(width: 760, height: 600)
            .windowResizability(.contentSize)
    }
}

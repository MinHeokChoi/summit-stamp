import SwiftUI

@main
@MainActor
struct HikerApp: App {
    private let container: AppContainer

    init() {
        container = AppContainer()
    }

    var body: some Scene {
        WindowGroup {
            RootView(container: container)
        }
    }
}

import SwiftUI
import HikerMapFeature

@MainActor
struct RootView: View {
    @Bindable private var container: AppContainer
    @Environment(\.scenePhase) private var scenePhase
    @State private var selectedTab: Int

    init(container: AppContainer) {
        self.container = container
        _selectedTab = State(
            initialValue: ProcessInfo.processInfo.arguments.contains("--initial-tab-passport") ? 1 : 0
        )
    }

    var body: some View {
        VStack(spacing: 0) {
            AuthenticationShell(coordinator: container.authenticationCoordinator)
            Divider()

            TabView(selection: $selectedTab) {
                NavigationStack {
                    MapFeatureView(
                        viewModel: container.currentMapViewModel,
                        revision: container.projectionRevision
                    )
                        .id(container.projectionRevision)
                        .navigationTitle("Map")
                }
                .tabItem {
                    Label("Map", systemImage: "map")
                }
                .tag(0)

                NavigationStack {
                    container.makePassportFeatureView()
                        .navigationTitle("Passport")
                }
                .tabItem {
                    Label("Passport", systemImage: "book.closed")
                }
                .tag(1)
                NavigationStack {
                    container.makeSocialFeatureView()
                        .navigationTitle("Friends")
                }
                .tabItem {
                    Label("Friends", systemImage: "person.2")
                        .accessibilityIdentifier("social.tab")
                }
                .tag(2)
            }
        }
        .task {
            await container.loadLocalPassportState()
            await container.synchronizeSelfPassportIfAuthenticated()
            await container.refreshSocialIfAuthenticated()
        }
        .onChange(of: container.authenticationCoordinator.state) { _, state in
            let generation = container.authenticationStateWillChange(state)
            Task {
                await container.authenticationStateDidChange(
                    state,
                    generation: generation
                )
            }
        }
        .onChange(of: scenePhase) { _, phase in
            if phase != .active {
                container.socialAppDidBecomeInactive()
                return
            }

            Task {
                container.authenticationCoordinator.refreshStoredSessionState()
                await container.synchronizeSelfPassportIfAuthenticated()
                await container.refreshSocialIfAuthenticated()
            }
        }
    }
}

@MainActor
private struct AuthenticationShell: View {
    let coordinator: AuthenticationCoordinator

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Account")
                .font(.headline)

            Text(stateTitle)
                .accessibilityIdentifier("auth.state")

            if let errorMessage {
                Text(errorMessage)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("auth.error")
            }

            controls
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
    }

    @ViewBuilder
    private var controls: some View {
        switch coordinator.state {
        case .signedIn:
            Button("Sign out") {
                coordinator.signOut()
            }
            .accessibilityIdentifier("auth.sign-out")

        case .signingIn:
            Button("Cancel sign in") {
                coordinator.cancelSignIn()
            }
            .accessibilityIdentifier("auth.cancel")

        case .error(.unavailableConfiguration):
            Button("Sign in with Apple") {
                coordinator.beginSignIn()
            }
            .accessibilityIdentifier("auth.sign-in")
            .disabled(true)

        case .signedOut, .cancelled, .expired, .error:
            Button("Sign in with Apple") {
                coordinator.beginSignIn()
            }
            .accessibilityIdentifier("auth.sign-in")
        }
    }

    private var stateTitle: String {
        switch coordinator.state {
        case .signedOut:
            return "Signed out"
        case .signingIn:
            return "Signing in with Apple"
        case .signedIn:
            return "Signed in"
        case .cancelled:
            return "Sign-in cancelled"
        case .expired:
            return "Sign-in expired"
        case .error(.unavailableConfiguration):
            return "Sign-in unavailable"
        case .error:
            return "Sign-in failed"
        }
    }

    private var errorMessage: String? {
        switch coordinator.state {
        case .error(.unavailableConfiguration):
            return "Sign in with Apple is unavailable in this build."
        case .error:
            return "Sign in with Apple could not be completed. Try again."
        case .expired:
            return "Your saved session has expired. Sign in again."
        default:
            return nil
        }
    }
}

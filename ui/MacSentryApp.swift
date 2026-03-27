// MacSentry — MacSentryApp.swift
// App entry point + Python bridge via Process

import SwiftUI

@main
struct MacSentryApp: App {
    @StateObject private var scanState = ScanStateModel()

    var body: some Scene {
        WindowGroup {
            DashboardView()
                .environmentObject(scanState)
                .frame(minWidth: 900, minHeight: 680)
        }
        .windowStyle(.hiddenTitleBar)
        .commands {
            CommandGroup(replacing: .newItem) { }
        }
    }
}

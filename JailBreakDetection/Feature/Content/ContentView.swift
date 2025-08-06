//
//  ContentView.swift
//  JailBreakDetection
//
//  Created by Engin Bolat on 6.08.2025.
//

import SwiftUI

struct ContentView: View {
    @ObservedObject var viewModel: ContentViewViewModel = ContentViewViewModel()
    
    var body: some View {
        VStack {
            Image(systemName: "globe")
                .imageScale(.large)
                .foregroundStyle(.tint)
        }
        .onAppear() {
            viewModel.checkIsJailBroken()
        }
        .padding()
        .sheet(isPresented: $viewModel.isJailBrokenDevice) { JailBreakSheetBodyView() }
    }
}

#Preview {
    ContentView()
}

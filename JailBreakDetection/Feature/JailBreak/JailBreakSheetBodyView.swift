//
//  JailBreakSheetBodyView.swift
//  JailBreakDetection
//
//  Created by Engin Bolat on 6.08.2025.
//

import SwiftUI

struct JailBreakSheetBodyView: View {
    var body: some View {
        VStack(spacing: 16) {
            Text("🚨 Jailbreak Detected")
                .font(.title2)
                .fontWeight(.bold)
                .foregroundColor(.red)
            Text("You cannot use this x application with jailbroken device.")
                .font(.caption)
                .multilineTextAlignment(.center)
        }
        .padding()
        .presentationDetents([.height(200)])
        .interactiveDismissDisabled()
    }
}

#Preview {
    JailBreakSheetBodyView()
}

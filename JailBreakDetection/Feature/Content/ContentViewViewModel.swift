//
//  ContentViewViewModel.swift
//  JailBreakDetection
//
//  Created by Engin Bolat on 6.08.2025.
//

import Foundation
import UIKit

protocol ContentViewViewModelProtocol: ObservableObject {
    // Varaibles
    var isJailBrokenDevice: Bool { get set }
    
    // Functions
    func checkIsJailBroken()
}

final class ContentViewViewModel: ContentViewViewModelProtocol {
    @Published var isJailBrokenDevice: Bool = false
    
    func checkIsJailBroken() {
        if UIDevice.current.isJailBroken {
            isJailBrokenDevice = true
        } else {
            isJailBrokenDevice = false
        }
    }
}

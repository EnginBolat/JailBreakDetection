//
//  JailBreakService.swift
//  JailBreakDetection
//
//  Created by Engin Bolat on 6.08.2025.
//

import Foundation
import UIKit

// hasCydiaInstalled için bu izinler alınmalı
/**
 <key>LSApplicationQueriesSchemes</key>
 <array>
    <string>cydia</string>
    <string>sileo</string>
    <string>zbra</string>
    <string>undecimus</string>
    <string>filza</string>
 </array>
 */

extension UIDevice {
    var isSimulator: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }
    
    var isJailBroken: Bool {
        get {
            if UIDevice.current.isSimulator { return false }
            if JailBreakService.hasCydiaInstalled() { return true }
            if JailBreakService.isContainsSuspiciousApps() { return true}
            if JailBreakService.isSuspiciousSystemPathExists() { return true }
            if JailBreakService.canEditSystemFiles() { return true }
            if JailBreakService.hasSuspiciousSymlinks() { return true }
            if JailBreakService.hasSandBoxViolation() { return true }
            if JailBreakService.isDebuggerAttached() { return true}
            if JailBreakService.isUsingProxy() { return true}
            if JailBreakService.isRootUser() { return true}
            if JailBreakService.hasSuspiciousURLSchemes() { return true }
            if JailBreakService.hasSuspiciousFiles() { return true }
            if JailBreakService.canWriteOutsideSandbox() { return true }
            if JailBreakService.isCodeTampered() { return true }
            if JailBreakService.isDylibInjected() { return true }
            return false
        }
    }
}

protocol JailBreakDetectable {
    static func hasCydiaInstalled() -> Bool
    static func isContainsSuspiciousApps() -> Bool
    static func isSuspiciousSystemPathExists() -> Bool
    static func canEditSystemFiles() -> Bool
    static func hasSuspiciousSymlinks() -> Bool
    static func canWriteOutsideSandbox() -> Bool
    static func hasSandBoxViolation() -> Bool
    static func hasSuspiciousURLSchemes() -> Bool
    static func hasSuspiciousFiles() -> Bool
    static func isDylibInjected() -> Bool
    static func isDebuggerAttached() -> Bool
    static func isUsingProxy() -> Bool
    static func isRootUser() -> Bool
    static func isCodeTampered() -> Bool
}

private struct JailBreakService: JailBreakDetectable {
    private static var cydiaSchemes = ["cydia://","sileo://","zbra://"]
    
    static func hasCydiaInstalled() -> Bool {
        for scheme in cydiaSchemes {
            if let url = URL(string: scheme),
               UIApplication.shared.canOpenURL(url) {
                return true
            }
        }
        return false
    }
    
    static func isContainsSuspiciousApps() -> Bool {
        for path in suspiciousAppsPathToCheck {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        return false
    }
    
    static func isSuspiciousSystemPathExists() -> Bool {
        for path in suspiciousSystemPathsToCheck {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        return false
    }
    
    // MARK: Advanced Checks
    
    static func canEditSystemFiles() -> Bool {
        let jailBreakText = "Developer Insider"
        let path = "/private/" + jailBreakText
        
        do {
            try jailBreakText.write(toFile: path, atomically: true,encoding: .utf8)
            try FileManager.default.removeItem(atPath: path)
            return true
        } catch {
            return false
        }
    }
    
    /// Checks for symbolic links in system directories, which is common in rootless jailbreaks.
    static func hasSuspiciousSymlinks() -> Bool {
        let paths = ["/Library", "/usr/lib", "/bin", "/etc", "/var"]
        for path in paths {
            do {
                let attributes = try FileManager.default.attributesOfItem(atPath: path)
                if attributes[.type] as? FileAttributeType == .typeSymbolicLink {
                    return true
                }
            } catch {
                continue  // Path doesn't exist or other error, which is normal for some paths
            }
        }
        return false
    }
    
    /// Tries to write a file outside of the app's sandbox. This should fail on a non-jailbroken device.
      static func canWriteOutsideSandbox() -> Bool {
          let path = "/private/" + UUID().uuidString
          do {
              try "Jailbreak Test".write(toFile: path, atomically: true, encoding: .utf8)
              try FileManager.default.removeItem(atPath: path) // Clean up
              return true // Write was successful, sandbox is compromised
          } catch {
              return false // Write failed, which is the expected behavior
          }
      }
    
    static func hasSandBoxViolation() -> Bool {
        do {
            try "sandbox_test".write(toFile: "/private/sandbox_test", atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: "/private/sandbox_test")
            return true
        } catch {
            return false
        }
    }
    
    /// Checks for the presence of URL schemes used by popular jailbreak package managers.
       static func hasSuspiciousURLSchemes() -> Bool {
           // Obfuscating strings makes them harder to find and patch in the binary.
           let schemes = [
               String(bytes: [0x63, 0x79, 0x64, 0x69, 0x61], encoding: .utf8)!, // "cydia"
               String(bytes: [0x73, 0x69, 0x6c, 0x65, 0x6f], encoding: .utf8)!, // "sileo"
               String(bytes: [0x7a, 0x62, 0x72, 0x61], encoding: .utf8)!, // "zbra"
               String(bytes: [0x75, 0x6e, 0x64, 0x65, 0x63, 0x69, 0x6d, 0x75, 0x73], encoding: .utf8)!, // "undecimus"
               String(bytes: [0x66, 0x69, 0x6c, 0x7a, 0x61], encoding: .utf8)!  // "filza"
           ]
           
           for scheme in schemes {
               if let url = URL(string: "\(scheme)://"), UIApplication.shared.canOpenURL(url) {
                   return true
               }
           }
           return false
       }
       
       /// Checks if common jailbreak-related files exist on the filesystem.
       static func hasSuspiciousFiles() -> Bool {
           let paths = suspiciousAppsPathToCheck + suspiciousSystemPathsToCheck
           return check(paths: paths)
       }
    
    /// Checks if suspicious dynamic libraries (like Cydia Substrate or libhooker) have been loaded into the app's process.
        static func isDylibInjected() -> Bool {
            let suspiciousLibraries = [
                "SubstrateLoader.dylib",
                "libhooker.dylib",
                "SubstrateBootstrap.dylib",
                "libsubstitute.dylib",
                "libellekit.dylib"
            ]
            
            for library in suspiciousLibraries {
                // dlopen returns a non-nil handle if the library is loaded.
                if let handle = dlopen(library, RTLD_NOW), handle != nil {
                    dlclose(handle)
                    return true
                }
            }

            return false
        }
    
    /// Uses `sysctl` to check if a debugger is attached to the process.
    static func isDebuggerAttached() -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        let result = sysctl(&mib, u_int(mib.count), &info, &size, nil, 0)
        
        // A non-zero result indicates an error, so we can't be sure.
        // The P_TRACED flag is set when a process is being debugged.
        return result == 0 && (info.kp_proc.p_flag & P_TRACED) != 0
    }
    
    static func isUsingProxy() -> Bool {
        if let proxySettings = CFNetworkCopySystemProxySettings()?.takeUnretainedValue() as? [AnyHashable: Any] {
            if let httpProxy = proxySettings["HTTPProxy"] {
                return true
            }
        }
        return false
    }
    
    /// Checks if the current user is root (uid 0).
    static func isRootUser() -> Bool {
        return getuid() == 0
    }

    /// Checks if the app has been tampered with (e.g., resigned or installed via unofficial means).
    static func isCodeTampered() -> Bool {
        // App Store apps must have this file. Apps from TrollStore or re-signed apps might not.
        guard Bundle.main.path(forResource: "embedded", ofType: "mobileprovision") != nil else {
            return true // Suspicious if missing
        }
        
        // Another check: The bundle path shouldn't contain suspicious keywords.
        // Apps installed by TrollStore may have paths like /var/containers/Bundle/Application/{UUID}/TrollStore.app
        let path = Bundle.main.bundlePath.lowercased()
        let suspiciousKeywords = ["/var/jb", "trollstore", "/private/var/containers"]
        for keyword in suspiciousKeywords {
            if path.contains(keyword) {
                return true
            }
        }
        
        return false
    }
    
    // MARK: - Private Helper
       
       /// A private helper function to check for the existence of files at given paths.
    private static func check(paths: [String]) -> Bool {
        let fileManager = FileManager.default
        for path in paths {
            if fileManager.fileExists(atPath: path) {
                return true
            }
        }
        return false
    }
     
    static var suspiciousAppsPathToCheck: [String] {
        return [
            // Traditional jailbreaks
            "/Applications/Cydia.app",
            "/Applications/blackra1n.app",
            "/Applications/FakeCarrier.app",
            "/Applications/Icy.app",
            "/Applications/IntelliScreen.app",
            "/Applications/MxTube.app",
            "/Applications/RockApp.app",
            "/Applications/SBSettings.app",
            "/Applications/WinterBoard.app",
            
            // Modern jailbreaks
            "/Applications/Palera1n.app",
            "/Applications/Sileo.app",
            "/Applications/Zebra.app",
            "/Applications/TrollStore.app",
            "/var/containers/Bundle/Application/TrollStore.app",
            
            // Checkra1n
            "/Applications/checkra1n.app",
            
            // Rootless jailbreak paths
            "/var/jb/Applications/Cydia.app",
            "/var/jb/Applications/Sileo.app",
            "/var/jb/Applications/Zebra.app"
        ]
    }
    
    static var suspiciousSystemPathsToCheck: [String] {
        return [
            // Traditional paths
            "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
            "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
            "/private/var/lib/apt",
            "/private/var/lib/cydia",
            "/private/var/mobile/Library/SBSettings/Themes",
            "/private/var/stash",
            "/private/var/tmp/cydia.log",
            "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
            "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
            "/usr/bin/sshd",
            "/usr/libexec/sftp-server",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/bin/bash",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            
            // Modern jailbreak paths
            "/var/jb", // Rootless jailbreak root
            "/var/binpack", // Checkm8 jailbreak
            "/var/containers/Bundle/tweaksupport",
            "/var/mobile/Library/palera1n",
            "/var/mobile/Library/xyz.willy.Zebra",
            "/var/lib/undecimus",
            
            // Palera1n specific
            "/var/jb/basebin",
            "/var/jb/usr",
            "/var/jb/etc",
            "/var/jb/Library",
            "/var/jb/.installed_palera1n",
            "/var/binpack/Applications",
            "/var/binpack/usr",
            
            // TrollStore
            "/var/containers/Bundle/Application/trollstorehelper",
            "/var/containers/Bundle/trollstore",
            
            // Bootstrap files
            "/var/jb/preboot",
            "/var/jb/var"
        ]
    }
}

enum JailBreakThreatType: String {
    case proxy
    case debugger
    case dylibInjection
    case rootAccess
    case cydiaDetected
    case tamperDetected
    case symbolicLink
    case sandboxViolation
}

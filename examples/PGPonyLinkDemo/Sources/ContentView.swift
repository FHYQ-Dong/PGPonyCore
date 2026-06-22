// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

import SwiftUI

@MainActor
final class LinkDecryptModel: ObservableObject {
    @Published var pin = ""
    @Published var ciphertext = LinkDecryptDemo.sampleCiphertext
    @Published var logText = ""
    @Published var result: String?
    @Published var running = false

    func go() {
        guard !running, !pin.isEmpty else { return }
        running = true
        result = nil
        logText = ""
        let pin = pin
        let ciphertext = ciphertext
        Task {
            do {
                let plaintext = try await LinkDecryptDemo.run(
                    ciphertextArmored: ciphertext, userPIN: pin
                ) { line in
                    Task { @MainActor in self.logText += line + "\n" }
                }
                self.result = plaintext
                self.logText += "DONE.\n"
            } catch {
                self.logText += "ERROR: \(error.localizedDescription)\n"
            }
            self.running = false
        }
    }
}

struct ContentView: View {
    @StateObject private var model = LinkDecryptModel()

    var body: some View {
        NavigationStack {
            Form {
                Section("User PIN (PW1)") {
                    SecureField("PIN", text: $model.pin)
                        .keyboardType(.numberPad)
                }
                Section("Ciphertext (encrypted to the [E] subkey)") {
                    TextEditor(text: $model.ciphertext)
                        .font(.system(.caption, design: .monospaced))
                        .frame(minHeight: 140)
                }
                Section {
                    Button(model.running ? "Working…" : "Link card & decrypt") {
                        model.go()
                    }
                    .disabled(model.running || model.pin.isEmpty)
                }
                if let result = model.result {
                    Section("Decrypted plaintext") {
                        Text(result).font(.system(.body, design: .monospaced))
                            .foregroundStyle(.green)
                    }
                }
                Section("Log") {
                    Text(model.logText.isEmpty ? "—" : model.logText)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
            .navigationTitle("PGPony Link Demo")
        }
    }
}

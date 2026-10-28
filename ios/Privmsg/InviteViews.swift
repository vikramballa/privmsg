import CoreImage.CIFilterBuiltins
import SwiftUI
import VisionKit

/// Make a one-time invite and pass it on.
struct InviteSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var code: String?
    @State private var working = false
    @State private var error: String?
    @State private var copied = false

    var body: some View {
        NavigationStack {
            Form {
                if let code {
                    Section {
                        if let image = qrImage(code) {
                            Image(uiImage: image)
                                .interpolation(.none)
                                .resizable()
                                .scaledToFit()
                                .frame(maxWidth: 280)
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 8)
                        }
                    } footer: {
                        Text("Together? Let \(name) scan this with privmsg. Safest: nothing goes through another app.")
                    }
                    Section {
                        Text(code)
                            .font(.system(.footnote, design: .monospaced))
                            .textSelection(.enabled)
                            .lineLimit(4)
                        Button(copied ? "Copied for 3 minutes" : "Copy the code", systemImage: "doc.on.doc") {
                            Clipboard.copyPrivately(code)
                            copied = true
                        }
                        ShareLink(item: code) {
                            Label("Send it with another app", systemImage: "square.and.arrow.up")
                        }
                    } footer: {
                        Text("Apart? Send the code to \(name) any way you like (Signal, email, a text…). It works once. When they enter it, you're connected; compare safety numbers later to be sure nobody swapped it.")
                    }
                } else {
                    Section {
                        TextField("Their name (only you will see it)", text: $name)
                            .textInputAutocapitalization(.words)
                            .autocorrectionDisabled()
                            .onSubmit { Task { await make() } }
                    } header: {
                        Text("Who are you inviting?")
                    }
                    if let error {
                        Section { Text(error).foregroundStyle(.red) }
                    }
                    Section {
                        Button {
                            Task { await make() }
                        } label: {
                            HStack {
                                Text("Make an invite")
                                if working { Spacer(); ProgressView() }
                            }
                        }
                        .disabled(working || name.trimmingCharacters(in: .whitespaces).isEmpty)
                    } footer: {
                        if working { Text("Getting a fresh address for this chat (a few seconds)…") }
                    }
                }
            }
            .navigationTitle(code == nil ? "Invite a friend" : "Invite for \(name)")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    private func make() async {
        working = true
        error = nil
        defer { working = false }
        do {
            code = try await model.createInvite(for: name)
        } catch {
            self.error = describe(error)
        }
    }
}

/// Use an invite code someone gave you.
struct AddContactSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    /// Called with the new contact's name once added.
    let added: (String) -> Void

    @State private var code = ""
    @State private var name = ""
    @State private var scanning = false
    @State private var working = false
    @State private var error: String?

    private var codeLooksRight: Bool { isInviteCode(text: code) }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("privmsg1:…", text: $code, axis: .vertical)
                        .accessibilityIdentifier("codeField")
                        .font(.system(.footnote, design: .monospaced))
                        .lineLimit(3...6)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    HStack {
                        // The system Paste button reads the clipboard only
                        // when tapped, without a permission prompt.
                        PasteButton(payloadType: String.self) { strings in
                            if let text = strings.first {
                                Task { @MainActor in code = text.trimmingCharacters(in: .whitespacesAndNewlines) }
                            }
                        }
                        .labelStyle(.titleAndIcon)
                        Spacer()
                        if DataScannerViewController.isSupported {
                            Button("Scan", systemImage: "qrcode.viewfinder") { scanning = true }
                                .buttonStyle(.bordered)
                        }
                    }
                } header: {
                    Text("Invite code")
                } footer: {
                    if !code.isEmpty && !codeLooksRight {
                        Text("That doesn't look like a whole invite code. It starts with privmsg1:")
                            .foregroundStyle(.orange)
                    }
                }
                Section("What do you want to call them?") {
                    TextField("Name (only you will see it)", text: $name)
                        .accessibilityIdentifier("nameField")
                        .textInputAutocapitalization(.words)
                        .autocorrectionDisabled()
                }
                if let error {
                    Section { Text(error).foregroundStyle(.red) }
                }
                Section {
                    Button {
                        Task { await add() }
                    } label: {
                        HStack {
                            Text("Connect")
                            if working { Spacer(); ProgressView() }
                        }
                    }
                    .disabled(working || !codeLooksRight || name.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
            .navigationTitle("Enter an invite")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
            .fullScreenCover(isPresented: $scanning) {
                QRScanner { text in
                    code = text
                    scanning = false
                }
                .ignoresSafeArea()
                .overlay(alignment: .topTrailing) {
                    Button("Cancel") { scanning = false }
                        .buttonStyle(.borderedProminent)
                        .padding()
                }
            }
        }
    }

    private func add() async {
        working = true
        error = nil
        defer { working = false }
        let name = name.trimmingCharacters(in: .whitespaces)
        do {
            try await model.acceptInvite(code: code, name: name)
            model.show("\(name) added. Say hi! They'll see it as soon as they're online.")
            dismiss()
            added(name)
        } catch {
            self.error = describe(error)
        }
    }
}

/// A QR code for `text`, drawn on the phone.
private func qrImage(_ text: String) -> UIImage? {
    let filter = CIFilter.qrCodeGenerator()
    filter.message = Data(text.utf8)
    filter.correctionLevel = "M"
    guard let output = filter.outputImage,
          let image = CIContext().createCGImage(output, from: output.extent)
    else { return nil }
    return UIImage(cgImage: image)
}

/// The camera, looking for an invite QR code. VisionKit reads it on the
/// phone; nothing is sent anywhere.
private struct QRScanner: UIViewControllerRepresentable {
    let found: (String) -> Void

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            isHighlightingEnabled: true
        )
        scanner.delegate = context.coordinator
        try? scanner.startScanning()
        return scanner
    }

    func updateUIViewController(_ controller: DataScannerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(found: found) }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let found: (String) -> Void
        private var done = false

        init(found: @escaping (String) -> Void) { self.found = found }

        func dataScanner(_ scanner: DataScannerViewController, didAdd items: [RecognizedItem], allItems: [RecognizedItem]) {
            for item in items {
                if case let .barcode(code) = item, let text = code.payloadStringValue,
                   isInviteCode(text: text), !done
                {
                    done = true
                    scanner.stopScanning()
                    found(text.trimmingCharacters(in: .whitespacesAndNewlines))
                }
            }
        }
    }
}

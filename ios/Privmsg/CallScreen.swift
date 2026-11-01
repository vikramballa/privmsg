import SwiftUI

/// The whole screen during a call: who, how it's going, and the buttons.
struct CallScreen: View {
    @Environment(AppModel.self) private var model
    let call: CallView

    var body: some View {
        ZStack {
            Color(.systemBackground).ignoresSafeArea()
            VStack(spacing: 16) {
                Spacer()
                Image(systemName: "person.crop.circle.fill")
                    .font(.system(size: 88))
                    .foregroundStyle(.secondary)
                Text(call.displayName)
                    .font(.largeTitle.bold())
                    .lineLimit(1)
                    .minimumScaleFactor(0.5)
                stageLine
                    .font(.headline)
                    .foregroundStyle(.secondary)
                Label("Private call: no IP address is shared, and no server sees who you call.",
                      systemImage: "lock.fill")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
                Spacer()
                buttons
                    .padding(.bottom, 48)
            }
            .padding()
        }
    }

    @ViewBuilder
    private var stageLine: some View {
        switch call.stage {
        case .calling:
            Text("Calling… (setting up a private line takes 10–30 seconds)")
                .multilineTextAlignment(.center)
        case .ringing:
            Text("is calling you")
        case .connecting:
            Text("Connecting over a private line…")
        case .talking:
            TimelineView(.periodic(from: .now, by: 1)) { context in
                let secs = Int(context.date.timeIntervalSince(model.talkingSince ?? context.date))
                Text(String(format: "%d:%02d", secs / 60, secs % 60) + (call.muted ? " · muted" : ""))
                    .monospacedDigit()
            }
        }
    }

    @ViewBuilder
    private var buttons: some View {
        if call.stage == .ringing {
            HStack(spacing: 64) {
                round("phone.down.fill", "Decline", .red) { Task { await model.endCall() } }
                round("phone.fill", "Answer", .green) { Task { await model.answerCall() } }
            }
        } else {
            HStack(spacing: 40) {
                round(call.muted ? "mic.slash.fill" : "mic.fill", call.muted ? "Unmute" : "Mute",
                      call.muted ? .orange : .gray) {
                    model.toggleMute()
                }
                .disabled(call.stage != .talking)
                round("phone.down.fill", "End", .red) { Task { await model.endCall() } }
                round(model.onSpeaker ? "speaker.wave.3.fill" : "speaker.fill", "Speaker",
                      model.onSpeaker ? .blue : .gray) {
                    model.toggleSpeaker()
                }
            }
        }
    }

    private func round(
        _ symbol: String, _ label: String, _ color: Color, action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            VStack(spacing: 8) {
                Image(systemName: symbol)
                    .font(.title)
                    .foregroundStyle(.white)
                    .frame(width: 72, height: 72)
                    .background(color, in: Circle())
                Text(label)
                    .font(.caption)
                    .foregroundStyle(.primary)
            }
        }
        .accessibilityLabel(label)
    }
}

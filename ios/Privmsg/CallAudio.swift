import AVFoundation
import Foundation
import os

/// The microphone and speaker during a call. On only while talking, so the
/// microphone is never open otherwise. Apple's voice processing (the same
/// as for phone calls) cancels echo and noise.
///
/// The audio moves straight between the sound hardware and the messenger,
/// in the hardware's own small blocks (about 10 ms): the microphone through
/// a sink node, the speaker through a source node that asks the messenger
/// for exactly what it is about to play. (A microphone *tap* would hand
/// over 100 ms or more at a time, which costs delay.) If the sink node
/// hears nothing, it falls back to a tap.
///
/// No CallKit: it would put every call in the phone's call history, which
/// iCloud syncs to Apple.
final class CallAudio {
    private let engine = AVAudioEngine()
    private let messenger: Messenger
    private let format: AVAudioFormat
    /// Microphone samples handed over so far.
    private let heard = Counter()
    private var source: AVAudioSourceNode?
    private var sink: AVAudioSinkNode?
    /// The sink node gave nothing: use a tap instead.
    private var tapped = false
    private var running = false
    private var onSpeaker = false
    private var observers: [NSObjectProtocol] = []
    private static let log = Logger(subsystem: "privmsg", category: "call-audio")

    init(messenger: Messenger) {
        self.messenger = messenger
        format = AVAudioFormat(
            commonFormat: .pcmFormatFloat32, sampleRate: Double(callSampleRate()),
            channels: 1, interleaved: false)!
    }

    /// Ask for the microphone the first time (before calling or answering).
    static func askForMicrophone() async -> Bool {
        await AVAudioApplication.requestRecordPermission()
    }

    func start() throws {
        let session = AVAudioSession.sharedInstance()
        try session.setCategory(.playAndRecord, mode: .voiceChat, options: [.allowBluetoothHFP])
        try? session.setPreferredSampleRate(Double(callSampleRate()))
        try? session.setPreferredIOBufferDuration(0.01)
        try session.setActive(true)
        try wire()
        running = true
        watchMicrophone()

        let center = NotificationCenter.default
        // Headphones in or out, Bluetooth, another app: the engine stops
        // and has to be set up again.
        observers.append(center.addObserver(
            forName: .AVAudioEngineConfigurationChange, object: engine, queue: .main
        ) { [weak self] _ in self?.restart() })
        observers.append(center.addObserver(
            forName: AVAudioSession.interruptionNotification, object: nil, queue: .main
        ) { [weak self] note in
            let raw = note.userInfo?[AVAudioSessionInterruptionTypeKey] as? UInt
            if raw.flatMap(AVAudioSession.InterruptionType.init) == .ended {
                try? AVAudioSession.sharedInstance().setActive(true)
                self?.restart()
            }
        })
    }

    func stop() {
        running = false
        observers.forEach(NotificationCenter.default.removeObserver)
        observers = []
        unwire()
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
    }

    /// The loudspeaker instead of the earpiece, or back.
    func useSpeaker(_ on: Bool) {
        onSpeaker = on
        try? AVAudioSession.sharedInstance().overrideOutputAudioPort(on ? .speaker : .none)
    }

    private func wire() throws {
        let input = engine.inputNode
        if !input.isVoiceProcessingEnabled {
            try input.setVoiceProcessingEnabled(true)
        }
        let micFormat = input.outputFormat(forBus: 0)
        guard micFormat.sampleRate > 0, micFormat.channelCount > 0 else {
            throw CallAudioError.noMicrophone
        }
        if tapped {
            input.installTap(
                onBus: 0, bufferSize: 4_800, format: micFormat,
                block: Self.tapBlock(messenger, heard))
        } else {
            let sink = AVAudioSinkNode(receiverBlock: Self.sinkBlock(messenger, heard, micFormat))
            engine.attach(sink)
            engine.connect(input, to: sink, format: micFormat)
            self.sink = sink
        }
        let source = AVAudioSourceNode(format: format, renderBlock: Self.speakerBlock(messenger))
        engine.attach(source)
        engine.connect(source, to: engine.mainMixerNode, format: format)
        self.source = source
        engine.prepare()
        try engine.start()
    }

    private func unwire() {
        engine.stop()
        engine.inputNode.removeTap(onBus: 0)
        if let sink {
            engine.detach(sink)
        }
        if let source {
            engine.detach(source)
        }
        sink = nil
        source = nil
    }

    private func restart() {
        guard running else { return }
        unwire()
        do {
            try wire()
            useSpeaker(onSpeaker)
        } catch {
            Self.log.error("could not restart the call audio: \(error.localizedDescription)")
        }
    }

    /// If the sink node hears nothing in its first moments, use a tap.
    private func watchMicrophone() {
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak self] in
            guard let self, self.running, !self.tapped, self.heard.value == 0 else { return }
            Self.log.notice("no microphone audio through the sink node; using a tap")
            self.tapped = true
            self.restart()
        }
    }

    // The audio blocks run on the audio thread: they touch only what they
    // are given.

    private static func sinkBlock(
        _ messenger: Messenger, _ heard: Counter, _ micFormat: AVAudioFormat
    ) -> AVAudioSinkNodeReceiverBlock {
        let rate = UInt32(micFormat.sampleRate.rounded())
        let stride = micFormat.isInterleaved ? Int(micFormat.channelCount) : 1
        return { _, frames, list in
            let buffers = UnsafeMutableAudioBufferListPointer(UnsafeMutablePointer(mutating: list))
            guard let first = buffers.first,
                let data = first.mData?.assumingMemoryBound(to: Float.self)
            else { return noErr }
            push(data, count: Int(frames), stride: stride, rate: rate, messenger, heard)
            return noErr
        }
    }

    private static func tapBlock(_ messenger: Messenger, _ heard: Counter) -> AVAudioNodeTapBlock {
        return { buffer, _ in
            guard let data = buffer.floatChannelData?[0] else { return }
            push(
                data, count: Int(buffer.frameLength), stride: buffer.stride,
                rate: UInt32(buffer.format.sampleRate.rounded()), messenger, heard)
        }
    }

    private static func push(
        _ data: UnsafeMutablePointer<Float>, count: Int, stride: Int, rate: UInt32,
        _ messenger: Messenger, _ heard: Counter
    ) {
        guard count > 0 else { return }
        var samples = [Float](repeating: 0, count: count)
        for i in 0..<count {
            samples[i] = data[i * stride]
        }
        messenger.pushMic(samples: samples, rate: rate)
        heard.add(count)
    }

    private static func speakerBlock(_ messenger: Messenger) -> AVAudioSourceNodeRenderBlock {
        return { _, _, frames, list in
            let wanted = Int(frames)
            let samples = messenger.pullSpeaker(count: frames)
            let n = min(samples.count, wanted)
            for buffer in UnsafeMutableAudioBufferListPointer(list) {
                guard let data = buffer.mData?.assumingMemoryBound(to: Float.self) else { continue }
                samples.withUnsafeBufferPointer { from in
                    if let base = from.baseAddress, n > 0 {
                        data.update(from: base, count: n)
                    }
                }
                (data + n).update(repeating: 0, count: wanted - n)
            }
            return noErr
        }
    }
}

enum CallAudioError: LocalizedError {
    case noMicrophone

    var errorDescription: String? {
        "No microphone is available."
    }
}

/// A count shared with the audio thread.
final class Counter: @unchecked Sendable {
    private var count = 0
    private let lock = OSAllocatedUnfairLock()

    func add(_ n: Int) {
        lock.withLock { count += n }
    }

    var value: Int {
        lock.withLock { count }
    }
}

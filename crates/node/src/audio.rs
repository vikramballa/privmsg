//! The computer's microphone and speaker during a call. They are opened when
//! the talking starts and closed when the call ends, so the microphone is
//! never on otherwise. Whatever format the devices use is turned into the
//! call's 48 kHz mono and back. An echo canceller keeps the other person
//! from hearing themselves through your speakers; headphones still sound
//! best.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{FromSample, SampleFormat, SizedSample, Stream, StreamConfig};
use privmsg_node::call::{AudioPipe, MakeProcessor, Processor, Resampler, RATE};
use sonora::config::{EchoCanceller, GainController2, HighPassFilter, NoiseSuppression};
use sonora::{AudioProcessing, Config};

/// The echo canceller works on 10 ms at a time.
const STEP: usize = RATE as usize / 100;

/// The open microphone and speaker. Dropping it closes both.
pub(crate) struct Devices {
    _input: Stream,
    _output: Stream,
}

impl Devices {
    /// Open the default microphone and speaker for the call on `pipe`.
    pub(crate) fn open(pipe: &AudioPipe) -> Result<Self> {
        let host = cpal::default_host();
        let mic = host.default_input_device().context("no microphone found")?;
        let speaker = host.default_output_device().context("no speaker found")?;
        let input = mic
            .default_input_config()
            .context("the microphone can't be used")?;
        let output = speaker
            .default_output_config()
            .context("the speaker can't be used")?;

        let (format, config) = (input.sample_format(), input.config());
        let input = match format {
            SampleFormat::F32 => listen::<f32>(&mic, config, pipe.clone()),
            SampleFormat::I16 => listen::<i16>(&mic, config, pipe.clone()),
            SampleFormat::I32 => listen::<i32>(&mic, config, pipe.clone()),
            SampleFormat::U16 => listen::<u16>(&mic, config, pipe.clone()),
            other => bail!("the microphone uses {other} samples, which isn't supported"),
        }?;
        let (format, config) = (output.sample_format(), output.config());
        let output = match format {
            SampleFormat::F32 => play::<f32>(&speaker, config, pipe.clone()),
            SampleFormat::I16 => play::<i16>(&speaker, config, pipe.clone()),
            SampleFormat::I32 => play::<i32>(&speaker, config, pipe.clone()),
            SampleFormat::U16 => play::<u16>(&speaker, config, pipe.clone()),
            other => bail!("the speaker uses {other} samples, which isn't supported"),
        }?;
        input.play().context("start the microphone")?;
        output.play().context("start the speaker")?;
        Ok(Self {
            _input: input,
            _output: output,
        })
    }
}

fn listen<T>(device: &cpal::Device, config: StreamConfig, pipe: AudioPipe) -> Result<Stream>
where
    T: SizedSample,
    f32: FromSample<T>,
{
    let channels = usize::from(config.channels.max(1));
    let mut resample = Resampler::new(config.sample_rate, RATE);
    let (mut mono, mut out) = (Vec::new(), Vec::new());
    let stream = device.build_input_stream(
        config,
        move |data: &[T], _: &cpal::InputCallbackInfo| {
            mono.clear();
            mono.extend(data.chunks(channels).map(|frame| {
                frame
                    .iter()
                    .map(|s| <f32 as FromSample<T>>::from_sample_(*s))
                    .sum::<f32>()
                    / frame.len() as f32
            }));
            out.clear();
            resample.run(&mono, &mut out);
            pipe.push_mic(&out);
        },
        |e| tracing::warn!("microphone: {e}"),
        None,
    )?;
    Ok(stream)
}

fn play<T>(device: &cpal::Device, config: StreamConfig, pipe: AudioPipe) -> Result<Stream>
where
    T: SizedSample + FromSample<f32>,
{
    let channels = usize::from(config.channels.max(1));
    let mut resample = Resampler::new(RATE, config.sample_rate);
    let (mut call, mut ready) = (Vec::new(), Vec::new());
    let stream = device.build_output_stream(
        config,
        move |data: &mut [T], _: &cpal::OutputCallbackInfo| {
            let frames = data.len() / channels;
            // What this block needs, taken from the call in one go (the
            // pipe sizes its reserve by it).
            while ready.len() < frames {
                let wanted = frames - ready.len();
                let n = (wanted as f64 * resample.step()).ceil() as usize + 1;
                call.resize(n.min(RATE as usize), 0.0);
                pipe.pull_speaker(&mut call);
                resample.run(&call, &mut ready);
            }
            for (frame, sample) in data.chunks_mut(channels).zip(ready.drain(..frames)) {
                frame.fill(T::from_sample_(sample));
            }
        },
        |e| tracing::warn!("speaker: {e}"),
        None,
    )?;
    Ok(stream)
}

/// The echo canceller (with noise suppression and level control), one per
/// call.
pub(crate) fn echo_canceller() -> MakeProcessor {
    Arc::new(|| {
        let config = Config {
            high_pass_filter: Some(HighPassFilter::default()),
            echo_canceller: Some(EchoCanceller::default()),
            noise_suppression: Some(NoiseSuppression::default()),
            gain_controller2: Some(GainController2::default()),
            ..Config::default()
        };
        let apm = AudioProcessing::builder()
            .config(config)
            .capture_config(sonora::StreamConfig::new(RATE, 1))
            .render_config(sonora::StreamConfig::new(RATE, 1))
            .build();
        Box::new(Echo {
            apm,
            scratch: vec![0.0; STEP],
        }) as Box<dyn Processor>
    })
}

struct Echo {
    apm: AudioProcessing,
    scratch: Vec<f32>,
}

impl Processor for Echo {
    fn render(&mut self, played: &[f32]) {
        for step in played.chunks_exact(STEP) {
            if let Err(e) = self
                .apm
                .process_render_f32(&[step], &mut [&mut self.scratch])
            {
                tracing::debug!("echo canceller (speaker side): {e:?}");
            }
        }
    }

    fn capture(&mut self, mic: &mut [f32]) {
        for step in mic.chunks_exact_mut(STEP) {
            self.scratch.copy_from_slice(step);
            if let Err(e) = self.apm.process_capture_f32(&[&self.scratch], &mut [step]) {
                tracing::debug!("echo canceller (microphone side): {e:?}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resampling_keeps_length_in_proportion_across_blocks() {
        for (from, to) in [
            (44_100, 48_000),
            (48_000, 44_100),
            (16_000, 48_000),
            (48_000, 48_000),
        ] {
            let mut r = Resampler::new(from, to);
            let mut out = Vec::new();
            let block: Vec<f32> = (0..441).map(|i| (i as f32 * 0.01).sin()).collect();
            for _ in 0..100 {
                r.run(&block, &mut out);
            }
            let expected = 44_100.0 * f64::from(to) / f64::from(from);
            let off = (out.len() as f64 - expected).abs();
            assert!(off <= 2.0, "{from}->{to}: {} vs {expected}", out.len());
            assert!(out.iter().all(|s| s.abs() <= 1.0));
        }
    }

    #[test]
    fn the_echo_canceller_takes_whole_chunks() {
        let mut echo = echo_canceller()();
        let mut mic = vec![0.1f32; privmsg_node::call::CHUNK];
        echo.render(&vec![0.2f32; privmsg_node::call::CHUNK]);
        echo.capture(&mut mic);
        assert!(mic.iter().all(|s| s.is_finite()));
    }
}

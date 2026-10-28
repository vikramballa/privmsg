//! Two messengers on the in-memory network, driven through the same API the
//! app uses.

use std::time::Duration;

use privmsg_transport::memory::MemoryNetwork;

use super::*;

#[derive(Default)]
struct Recorder {
    notices: Mutex<Vec<String>>,
    statuses: Mutex<Vec<ConnectionStatus>>,
}

impl Listener for Recorder {
    fn status(&self, status: ConnectionStatus) {
        self.statuses.lock().unwrap().push(status);
    }
    fn changed(&self) {}
    fn notice(&self, text: String) {
        self.notices.lock().unwrap().push(text);
    }
}

fn start(
    dir: &std::path::Path,
    net: &MemoryNetwork,
    create: bool,
) -> (Arc<Messenger>, Arc<Recorder>) {
    let recorder = Arc::new(Recorder::default());
    let net = net.clone();
    let messenger = Messenger::start(
        dir.to_path_buf(),
        Zeroizing::new("correct horse battery".into()),
        create,
        recorder.clone(),
        move |_, _| {
            move || {
                let net = net.clone();
                async move { Ok(net) }
            }
        },
    )
    .unwrap();
    (messenger, recorder)
}

/// Wait (up to 10 s) until `done` holds.
async fn until(what: &str, done: impl FnMut() -> bool) {
    until_for(what, Duration::from_secs(10), done).await
}

async fn until_for(what: &str, limit: Duration, mut done: impl FnMut() -> bool) {
    for _ in 0..limit.as_millis() / 50 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn two_phones_connect_and_talk() {
    let net = MemoryNetwork::default();
    let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, alice_hears) = start(a_dir.path(), &net, true);
    let (bob, bob_hears) = start(b_dir.path(), &net, true);
    until("online", || {
        alice.status() == ConnectionStatus::Online && bob.status() == ConnectionStatus::Online
    })
    .await;

    let code = bob.create_invite("alice".into()).await.unwrap();
    assert!(is_invite_code(code.clone()));
    assert_eq!(bob.invites(), vec!["alice".to_string()]);
    alice.accept_invite(code, "bob".into()).await.unwrap();
    until("the join", || bob.contacts().len() == 1).await;
    assert!(bob_hears.notices.lock().unwrap()[0].contains("alice joined"));
    assert!(bob.invites().is_empty(), "the invite is used up");

    alice
        .send("bob".into(), "hi\nthere \u{202E}".into())
        .await
        .unwrap();
    until("the message", || bob.messages("alice".into()).len() == 1).await;
    let got = &bob.messages("alice".into())[0];
    assert_eq!(got.text, "hi\nthere \u{FFFD}", "cleaned, line break kept");
    assert!(!got.outgoing);
    assert_eq!(bob.contacts()[0].unread, 1);
    bob.mark_read("alice".into());
    until("read", || bob.contacts()[0].unread == 0).await;

    bob.set_timer("alice".into(), Some(3600)).await.unwrap();
    until("the timer", || {
        alice.contacts()[0].disappear_label == "1 hour"
    })
    .await;
    until("the timer notice", || {
        !alice_hears.notices.lock().unwrap().is_empty()
    })
    .await;

    let (a, b) = (
        alice.safety_number("bob".into()).await.unwrap(),
        bob.safety_number("alice".into()).await.unwrap(),
    );
    assert_eq!(a, b, "both sides see the same safety number");

    assert!(alice.check_passphrase("correct horse battery".into()).await);
    assert!(!alice.check_passphrase("wrong".into()).await);

    let err = alice.send("nobody".into(), "x".into()).await.unwrap_err();
    assert!(err.to_string().contains("no contact"), "{err}");
    let err = alice.create_invite("  ".into()).await.unwrap_err();
    assert!(err.to_string().contains("name"), "{err}");

    // Back from a long time in the background: connections are made again,
    // on the same addresses.
    let before = alice_hears.statuses.lock().unwrap().len();
    alice.foreground(120);
    until("reconnect", || {
        let statuses = alice_hears.statuses.lock().unwrap();
        statuses[before..].contains(&ConnectionStatus::Connecting)
            && statuses.last() == Some(&ConnectionStatus::Online)
    })
    .await;
    bob.send("alice".into(), "still there?".into())
        .await
        .unwrap();
    until("a message after reconnecting", || {
        alice.messages("bob".into()).len() == 2
    })
    .await;

    alice.shutdown().await;
    assert_eq!(alice.status(), ConnectionStatus::Stopped);
    assert!(alice.send("bob".into(), "x".into()).await.is_err());
    bob.shutdown().await;

    // Reopens with everything kept.
    let (bob, _) = start(b_dir.path(), &net, false);
    assert_eq!(bob.messages("alice".into()).len(), 2);
    bob.shutdown().await;
}

#[tokio::test]
async fn decoys_queue_messages_and_settings_stick() {
    let net = MemoryNetwork::default();
    let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, _) = start(a_dir.path(), &net, true);
    let (bob, _) = start(b_dir.path(), &net, true);
    until("online", || {
        alice.status() == ConnectionStatus::Online && bob.status() == ConnectionStatus::Online
    })
    .await;
    let code = bob.create_invite("alice".into()).await.unwrap();
    alice.accept_invite(code, "bob".into()).await.unwrap();

    let mut settings = alice.settings();
    assert!(settings.tor, "Tor is on by default");
    settings.decoys = true;
    settings.auto_sleep_minutes = Some(10);
    alice.set_settings(settings.clone()).await.unwrap();
    assert_eq!(alice.settings(), settings);

    alice.send("bob".into(), "later".into()).await.unwrap();
    // Queued for the next decoy slot, 10 s away on average (exponential:
    // 2 minutes is very unlikely to be too short).
    until_for("delivery with a decoy", Duration::from_secs(120), || {
        bob.messages("alice".into()).len() == 1
    })
    .await;
    until("the queue to empty", || alice.queued() == 0).await;

    // Turning decoys off sends anything still waiting.
    settings.decoys = false;
    alice.set_settings(settings).await.unwrap();
    assert!(!alice.settings().decoys);
    alice.shutdown().await;
    bob.shutdown().await;
}

#[test]
fn wrong_passphrase_and_short_passphrase_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_string_lossy().to_string();
    let recorder: Arc<dyn Listener> = Arc::new(Recorder::default());
    let err = Messenger::create(path.clone(), "short".into(), recorder.clone())
        .err()
        .unwrap();
    assert!(err.to_string().contains("at least"), "{err}");
    assert!(!profile_exists(path.clone()));

    drop(Node::create(dir.path(), "correct horse battery").unwrap());
    let err = Messenger::open(path, "wrong".into(), recorder)
        .err()
        .unwrap();
    assert!(err.to_string().contains("wrong passphrase"), "{err}");
}

#[test]
fn timer_choices_start_with_off() {
    let choices = timer_choices();
    assert_eq!(choices[0].seconds, None);
    assert_eq!(choices[0].label, "off");
    assert_eq!(choices.len(), TIMERS.len() + 1);
}

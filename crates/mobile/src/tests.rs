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

/// A vault like the app's: the device key is sealed with a key that
/// `destroy` deletes.
#[derive(Default)]
struct TestVault {
    destroyed: Mutex<bool>,
}

impl KeyVault for TestVault {
    fn seal(&self, key: Vec<u8>) -> Result<Vec<u8>, MobileError> {
        self.unseal(key)
    }

    fn unseal(&self, sealed: Vec<u8>) -> Result<Vec<u8>, MobileError> {
        if *self.destroyed.lock().unwrap() {
            return Err(anyhow!("the vault's key is gone").into());
        }
        Ok(sealed.iter().map(|b| b ^ 0x5a).collect())
    }

    fn destroy(&self) -> Result<(), MobileError> {
        *self.destroyed.lock().unwrap() = true;
        Ok(())
    }
}

fn start(
    dir: &std::path::Path,
    net: &MemoryNetwork,
    create: bool,
) -> (Arc<Messenger>, Arc<Recorder>) {
    start_with(dir, net, create, Arc::new(TestVault::default()))
}

fn start_with(
    dir: &std::path::Path,
    net: &MemoryNetwork,
    create: bool,
    vault: Arc<TestVault>,
) -> (Arc<Messenger>, Arc<Recorder>) {
    let recorder = Arc::new(Recorder::default());
    let net = net.clone();
    let messenger = Messenger::start(
        dir.to_path_buf(),
        Zeroizing::new("correct horse battery".into()),
        create,
        Arc::new(AppVault(vault)),
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
async fn messages_and_chats_are_deleted_here_or_for_both() {
    let net = MemoryNetwork::default();
    let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, _) = start(a_dir.path(), &net, true);
    let (bob, bob_hears) = start(b_dir.path(), &net, true);
    until("online", || {
        alice.status() == ConnectionStatus::Online && bob.status() == ConnectionStatus::Online
    })
    .await;
    let code = bob.create_invite("alice".into()).await.unwrap();
    alice.accept_invite(code, "bob".into()).await.unwrap();
    until("the join", || bob.contacts().len() == 1).await;

    for text in ["one", "oops", "three"] {
        alice.send("bob".into(), text.into()).await.unwrap();
    }
    until("the messages", || bob.messages("alice".into()).len() == 3).await;
    let theirs = &bob.messages("alice".into())[0];
    assert!(
        !theirs.can_delete_for_everyone,
        "not Bob's to delete for Alice"
    );
    let err = bob
        .delete_message("alice".into(), theirs.id.clone(), true)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("own"), "{err}");

    // For everyone: gone on both phones.
    let oops = alice.messages("bob".into())[1].clone();
    assert!(oops.can_delete_for_everyone);
    alice
        .delete_message("bob".into(), oops.id, true)
        .await
        .unwrap();
    until("the delete", || bob.messages("alice".into()).len() == 2).await;
    let left: Vec<String> = bob
        .messages("alice".into())
        .into_iter()
        .map(|m| m.text)
        .collect();
    assert_eq!(left, ["one", "three"]);

    // Here only: Alice keeps hers.
    let one = bob.messages("alice".into())[0].id.clone();
    bob.delete_message("alice".into(), one, false)
        .await
        .unwrap();
    assert_eq!(bob.messages("alice".into()).len(), 1);
    assert_eq!(alice.messages("bob".into()).len(), 2);
    let err = bob
        .delete_message("alice".into(), "not an id".into(), false)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("gone"), "{err}");

    // The whole chat, for both: Bob is told who emptied it.
    alice.clear_chat("bob".into(), true).await.unwrap();
    assert!(alice.messages("bob".into()).is_empty());
    until("the clear", || bob.contacts()[0].cleared_by_them).await;
    assert!(bob.messages("alice".into()).is_empty());
    assert!(bob_hears
        .notices
        .lock()
        .unwrap()
        .iter()
        .any(|n| n.contains("alice cleared the chat")));

    // Here only, which also works offline.
    bob.send("alice".into(), "new start".into()).await.unwrap();
    until("the message", || alice.messages("bob".into()).len() == 1).await;
    bob.clear_chat("alice".into(), false).await.unwrap();
    assert!(bob.messages("alice".into()).is_empty());
    assert!(!bob.contacts()[0].cleared_by_them);
    assert_eq!(alice.messages("bob".into()).len(), 1);
    alice.shutdown().await;
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
    let vault: Arc<dyn KeyVault> = Arc::new(TestVault::default());
    let err = Messenger::create(
        path.clone(),
        "short".into(),
        vault.clone(),
        recorder.clone(),
    )
    .err()
    .unwrap();
    assert!(err.to_string().contains("at least"), "{err}");
    assert!(!profile_exists(path.clone(), vault.clone()));

    let app_vault = Arc::new(AppVault(vault.clone()));
    drop(Node::create_with(dir.path(), "correct horse battery", app_vault).unwrap());
    assert!(profile_exists(path.clone(), vault.clone()));
    let err = Messenger::open(path, "wrong".into(), vault, recorder)
        .err()
        .unwrap();
    assert!(err.to_string().contains("wrong passphrase"), "{err}");
}

#[tokio::test]
async fn erasing_tells_the_contact_and_leaves_nothing() {
    let net = MemoryNetwork::default();
    let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let a_path = a_dir.path().join("profile");
    let vault = Arc::new(TestVault::default());
    let (alice, _) = start_with(&a_path, &net, true, vault.clone());
    let (bob, bob_hears) = start(b_dir.path(), &net, true);
    until("online", || {
        alice.status() == ConnectionStatus::Online && bob.status() == ConnectionStatus::Online
    })
    .await;
    let code = bob.create_invite("alice".into()).await.unwrap();
    alice.accept_invite(code, "bob".into()).await.unwrap();
    until("the join", || bob.contacts().len() == 1).await;
    alice.send("bob".into(), "a secret".into()).await.unwrap();
    until("the message", || bob.messages("alice".into()).len() == 1).await;

    let err = alice
        .erase_identity("wrong".into(), true)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Wrong password"), "{err}");
    assert_eq!(alice.contacts().len(), 1, "nothing happened");

    let note = alice
        .erase_identity("correct horse battery".into(), true)
        .await
        .unwrap();
    assert!(note.contains("asked to delete"), "{note}");
    assert!(
        *vault.destroyed.lock().unwrap(),
        "the device key is destroyed"
    );
    assert!(!a_path.exists(), "nothing of the profile is left");
    until("stopped", || alice.status() == ConnectionStatus::Stopped).await;
    assert!(alice.send("bob".into(), "x".into()).await.is_err());

    until("bob hears", || bob.contacts().is_empty()).await;
    until("the notice", || {
        bob_hears
            .notices
            .lock()
            .unwrap()
            .iter()
            .any(|n| n.contains("erased their identity"))
    })
    .await;
    bob.shutdown().await;
}

#[test]
fn timer_choices_start_with_off() {
    let choices = timer_choices();
    assert_eq!(choices[0].seconds, None);
    assert_eq!(choices[0].label, "off");
    assert_eq!(choices.len(), TIMERS.len() + 1);
}

/// The real network: join a desktop's invite (`INVITE_CODE`) and send it
/// six messages, 20 s apart, through the same loop the phone runs (with
/// `WAIT_FOR_REPLY` set, waiting after the first for one from the desktop).
/// Tor comes from `PRIVMSG_TOR` unless built with `embedded-tor`. Run with
/// `cargo test -p privmsg-mobile live_sends -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the live network and a desktop invite"]
async fn live_sends_several_messages() {
    let code = std::env::var("INVITE_CODE").expect("set INVITE_CODE");
    let dir = tempfile::tempdir().unwrap();
    let recorder = Arc::new(Recorder::default());
    let phone = Messenger::create(
        dir.path().to_string_lossy().into(),
        "correct horse battery".into(),
        Arc::new(TestVault::default()),
        recorder.clone(),
    )
    .unwrap();
    until_for("online", Duration::from_secs(300), || {
        phone.status() == ConnectionStatus::Online
    })
    .await;
    phone.accept_invite(code, "desk".into()).await.unwrap();
    for i in 1..=6 {
        phone
            .send("desk".into(), format!("phone msg {i}"))
            .await
            .unwrap();
        eprintln!("sent phone msg {i}; status {:?}", phone.status());
        if i == 1 && std::env::var_os("WAIT_FOR_REPLY").is_some() {
            until_for("the desktop's reply", Duration::from_secs(600), || {
                phone.messages("desk".into()).iter().any(|m| !m.outgoing)
            })
            .await;
            eprintln!("got the reply");
        }
        tokio::time::sleep(Duration::from_secs(20)).await;
    }
    phone.shutdown().await;
}

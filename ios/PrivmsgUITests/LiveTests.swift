import XCTest

/// Drives the app in the simulator. `testFirstRun` needs nothing;
/// `testTalksToDesktop` needs the live network and a desktop privmsg that
/// made an invite: run with TEST_RUNNER_INVITE_CODE=<code> (and
/// TEST_RUNNER_PRIVMSG_TOR=<path to a tor program>, since a simulator build
/// without the linked-in Tor starts tor as a program), then send
/// "hi phone" from the desktop once it has the phone's message. The phone
/// then sends "delete me" and deletes it for everyone; once the desktop has
/// seen that, run `privmsg clear <name> everyone` there. Last, the phone
/// erases its identity, telling the desktop, which then shows that the
/// phone erased their identity and drops the chat. `testEraseIdentity`
/// needs nothing.
final class LiveTests: XCTestCase {
    private let passphrase = "simulator test passphrase"

    override func setUp() {
        continueAfterFailure = false
    }

    private func launch() -> XCUIApplication {
        let app = XCUIApplication()
        if let tor = ProcessInfo.processInfo.environment["PRIVMSG_TOR"] {
            app.launchEnvironment["PRIVMSG_TOR"] = tor
        }
        app.launch()
        return app
    }

    private func createProfile(_ app: XCUIApplication) {
        let password = app.secureTextFields["Password (at least 12 characters)"]
        XCTAssertTrue(password.waitForExistence(timeout: 10), "a fresh install starts with setup")
        password.tap()
        password.typeText(passphrase)
        let again = app.secureTextFields["Type it again"]
        again.tap()
        again.typeText(passphrase)
        app.buttons["Create my profile"].tap()
        XCTAssertTrue(app.navigationBars["Chats"].waitForExistence(timeout: 30))
    }

    private func screenshot(_ name: String) {
        let shot = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        shot.name = name
        shot.lifetime = .keepAlways
        add(shot)
    }

    func testFirstRun() {
        let app = launch()
        createProfile(app)
        screenshot("chats")
        app.buttons["Settings"].tap()
        XCTAssertTrue(app.switches["Hide my IP address with Tor"].waitForExistence(timeout: 5))
        screenshot("settings")
        app.buttons["Done"].tap()
        app.buttons["Add someone"].tap()
        app.buttons["Invite a friend"].tap()
        XCTAssertTrue(app.buttons["Make an invite"].waitForExistence(timeout: 5))
        screenshot("invite")
    }

    /// Settings → Erase my identity, with `password`: a wrong one first.
    private func erase(_ app: XCUIApplication, password: String) {
        app.buttons["Settings"].tap()
        let open = app.buttons["erase"]
        for _ in 0..<5 where !open.isHittable { app.swipeUp() }
        open.tap()
        let word = app.textFields["eraseWord"]
        XCTAssertTrue(word.waitForExistence(timeout: 5))
        word.tap()
        word.typeText("ERASE")
        let field = app.secureTextFields["erasePassword"]
        field.tap()
        field.typeText("not my password")
        let button = app.buttons["eraseEverything"]
        for _ in 0..<5 where !button.isHittable { app.swipeUp() }
        button.tap()
        app.alerts.buttons["Erase"].tap()
        let wrong = app.staticTexts["Wrong password."]
        XCTAssertTrue(wrong.waitForExistence(timeout: 30), "a wrong password changes nothing")
        screenshot("erase-wrong-password")

        for _ in 0..<5 where !field.isHittable { app.swipeDown() }
        field.tap()
        field.press(forDuration: 1.0)
        if app.menuItems["Select All"].waitForExistence(timeout: 2) {
            app.menuItems["Select All"].tap()
        }
        field.typeText(XCUIKeyboardKey.delete.rawValue)
        field.typeText(password)
        for _ in 0..<5 where !button.isHittable { app.swipeUp() }
        screenshot("erase-ready")
        button.tap()
        app.alerts.buttons["Erase"].tap()
        XCTAssertTrue(app.staticTexts["Erased"].waitForExistence(timeout: 120))
        screenshot("erased")
    }

    func testEraseIdentity() {
        var app = launch()
        createProfile(app)
        erase(app, password: passphrase)
        // Opened again, it starts fresh.
        app.terminate()
        app = launch()
        XCTAssertTrue(
            app.secureTextFields["Password (at least 12 characters)"].waitForExistence(timeout: 10),
            "nothing is left to unlock")
        screenshot("fresh-after-erase")
    }

    func testTalksToDesktop() throws {
        let env = ProcessInfo.processInfo.environment
        guard let code = env["INVITE_CODE"] else {
            throw XCTSkip("set TEST_RUNNER_INVITE_CODE to run against a desktop privmsg")
        }
        let app = launch()
        createProfile(app)
        XCTAssertTrue(app.staticTexts["Connected privately"].waitForExistence(timeout: 300),
                      "Tor and the mixnet come up")
        screenshot("online")

        app.buttons["Add someone"].tap()
        app.buttons["I have an invite code"].tap()
        let codeField = app.descendants(matching: .any)["codeField"]
        XCTAssertTrue(codeField.waitForExistence(timeout: 5))
        codeField.tap()
        codeField.typeText(code)
        let name = app.textFields["nameField"]
        name.tap()
        name.typeText("desk")
        app.buttons["Connect"].tap()

        let message = app.descendants(matching: .any)["messageField"]
        XCTAssertTrue(message.waitForExistence(timeout: 120), "opens the new chat")
        message.tap()
        message.typeText("hello from the iPhone")
        app.buttons["Send"].tap()
        XCTAssertTrue(app.staticTexts["hello from the iPhone"].waitForExistence(timeout: 60))
        screenshot("sent")

        XCTAssertTrue(app.staticTexts["hi phone"].waitForExistence(timeout: 900),
                      "the desktop's reply arrives")
        screenshot("reply")

        message.tap()
        message.typeText("delete me")
        app.buttons["Send"].tap()
        let doomed = app.staticTexts["delete me"]
        XCTAssertTrue(doomed.waitForExistence(timeout: 60))
        doomed.press(forDuration: 1.2)
        app.buttons["Delete…"].tap()
        let everyone = app.buttons["Delete for everyone"]
        XCTAssertTrue(everyone.waitForExistence(timeout: 5))
        screenshot("delete-choices")
        everyone.tap()
        XCTAssertTrue(gone(doomed, within: 60), "deleted here")
        screenshot("deleted")

        let cleared = app.descendants(matching: .any)
            .matching(NSPredicate(format: "label == %@", "desk cleared the chat")).firstMatch
        XCTAssertTrue(cleared.waitForExistence(timeout: 900), "the desktop empties the chat")
        XCTAssertFalse(app.staticTexts["hi phone"].exists, "for both sides")
        screenshot("cleared")

        app.navigationBars.buttons.element(boundBy: 0).tap()
        erase(app, password: passphrase)
        XCTAssertTrue(
            app.staticTexts["Your contact was asked to delete your chat."].exists,
            "the desktop was told")
    }

    private func gone(_ element: XCUIElement, within seconds: TimeInterval) -> Bool {
        let gone = expectation(for: NSPredicate(format: "exists == false"), evaluatedWith: element)
        return XCTWaiter.wait(for: [gone], timeout: seconds) == .completed
    }
}

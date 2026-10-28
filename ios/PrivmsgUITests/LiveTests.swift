import XCTest

/// Drives the app in the simulator. `testFirstRun` needs nothing;
/// `testTalksToDesktop` needs the live network and a desktop privmsg that
/// made an invite: run with TEST_RUNNER_INVITE_CODE=<code> (and
/// TEST_RUNNER_PRIVMSG_TOR=<path to a tor program>, since a simulator build
/// without the linked-in Tor starts tor as a program), then send
/// "hi phone" from the desktop once it has the phone's message.
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
    }
}

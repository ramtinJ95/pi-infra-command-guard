import assert from "node:assert/strict";
import {
	autoNotificationBackend,
	customSoundProcesses,
	detectTerminalNotificationBackend,
	isHerdrPane,
	loadApprovalAttentionSettings,
	nativeNotificationProcesses,
	parseApprovalAttentionSettings,
	parseHerdrNotificationOutput,
	sendTerminalNotification,
	shouldUseNativeNotification,
	terminalNotificationSequence,
} from "./attention.ts";
import { test } from "./test-harness.ts";

test("approval attention config is silent by default and resolves sound paths from the agent directory", () => {
	const configPath = "/home/test/.pi/agent/infra-command-guard.json";
	assert.deepEqual(parseApprovalAttentionSettings({}, configPath), {
		notifications: { enabled: false, backend: "auto" },
		sound: { enabled: false, path: null },
		integrations: { herdr: { enabled: true } },
	});
	assert.deepEqual(
		parseApprovalAttentionSettings(
			{
				notifications: { enabled: true, backend: "terminal" },
				sound: { enabled: true, path: "sounds/approval.wav" },
				integrations: { herdr: { enabled: false } },
			},
			configPath,
		),
		{
			notifications: { enabled: true, backend: "terminal" },
			sound: { enabled: true, path: "/home/test/.pi/agent/sounds/approval.wav" },
			integrations: { herdr: { enabled: false } },
		},
	);
	assert.throws(() => parseApprovalAttentionSettings({ notifications: { enabled: "yes" } }, configPath), /must be true or false/);
	assert.throws(() => parseApprovalAttentionSettings({ notifications: { provider: "kitty" } }, configPath), /unknown field/);
	assert.throws(() => parseApprovalAttentionSettings({ sound: { enabled: true, path: null } }, configPath), /path must be set/);
	assert.throws(() => parseApprovalAttentionSettings({ integrations: { herdr: { enabled: "yes" } } }, configPath), /must be true or false/);
	assert.deepEqual(loadApprovalAttentionSettings("/definitely/missing/infra-command-guard.json").settings, {
		notifications: { enabled: false, backend: "auto" },
		sound: { enabled: false, path: null },
		integrations: { herdr: { enabled: true } },
	});
});

test("Herdr integration requires pane markers and parses broker results", () => {
	assert.equal(isHerdrPane({ HERDR_ENV: "1", HERDR_SOCKET_PATH: "/tmp/herdr.sock" }), true);
	assert.equal(isHerdrPane({ HERDR_ENV: "1" }), false);
	assert.equal(isHerdrPane({ HERDR_SOCKET_PATH: "/tmp/herdr.sock" }), false);
	assert.deepEqual(
		parseHerdrNotificationOutput('{"result":{"shown":true,"reason":"shown","type":"notification_show"}}'),
		{ shown: true, reason: "shown" },
	);
	assert.deepEqual(
		parseHerdrNotificationOutput('{"result":{"shown":false,"reason":"disabled","type":"notification_show"}}'),
		{ shown: false, reason: "disabled" },
	);
	assert.deepEqual(parseHerdrNotificationOutput("not json"), { shown: false, reason: "invalid response" });

	const auto = parseApprovalAttentionSettings({ notifications: { enabled: true, backend: "auto" } }, "/tmp/config.json");
	const terminal = parseApprovalAttentionSettings(
		{ notifications: { enabled: true, backend: "terminal" } },
		"/tmp/config.json",
	);
	const herdr = { HERDR_ENV: "1", HERDR_SOCKET_PATH: "/tmp/herdr.sock" };
	assert.equal(shouldUseNativeNotification(auto, "darwin", herdr), true);
	assert.equal(shouldUseNativeNotification(auto, "linux", herdr), true);
	assert.equal(shouldUseNativeNotification(auto, "linux", {}), false);
	assert.equal(shouldUseNativeNotification(terminal, "darwin", herdr), false);
});

test("terminal notifications detect Kitty and Ghostty and emit their documented protocols", () => {
	assert.equal(detectTerminalNotificationBackend({ KITTY_WINDOW_ID: "1" }), "kitty");
	assert.equal(detectTerminalNotificationBackend({ TERM: "xterm-kitty" }), "kitty");
	assert.equal(detectTerminalNotificationBackend({ TERM_PROGRAM: "ghostty" }), "ghostty");
	assert.equal(detectTerminalNotificationBackend({ GHOSTTY_RESOURCES_DIR: "/tmp/ghostty" }), "ghostty");
	assert.equal(detectTerminalNotificationBackend({ TERM: "xterm-256color" }), undefined);
	assert.equal(autoNotificationBackend("darwin"), "native");
	assert.equal(autoNotificationBackend("win32"), "native");
	assert.equal(autoNotificationBackend("linux"), "terminal");

	const kitty = terminalNotificationSequence("kitty", "Title", "Body");
	assert.match(
		kitty,
		/^\u001b\]99;i=pi-infra-command-guard:d=0:f=cGktaW5mcmEtY29tbWFuZC1ndWFyZA==:s=c2lsZW50;/,
	);
	assert.ok(kitty.includes(Buffer.from("Title").toString("base64")));
	assert.ok(kitty.includes(Buffer.from("Body").toString("base64")));
	assert.ok(kitty.endsWith("\u001b]99;i=pi-infra-command-guard;\u001b\\"));
	assert.ok(!kitty.includes("i=pi-infra-command-guard;;"));
	assert.equal(terminalNotificationSequence("ghostty", "Title", "Body"), "\u001b]9;Title: Body\u001b\\");

	const writes: string[] = [];
	assert.equal(
		sendTerminalNotification("kitty", "Title", "Body", {
			isTTY: true,
			write(value: string | Uint8Array) {
				writes.push(String(value));
				return true;
			},
		} as never),
		true,
	);
	assert.deepEqual(writes, [kitty]);
	assert.equal(sendTerminalNotification("kitty", "Title", "Body", { isTTY: false, write() {} } as never), false);
});

test("native notifications and custom sound are independent", () => {
	assert.doesNotMatch(nativeNotificationProcesses("darwin")[0]!.args.join(" "), /sound name/);
	assert.doesNotMatch(nativeNotificationProcesses("win32")[0]!.args.join(" "), /SystemSounds/);
	assert.deepEqual(customSoundProcesses("/tmp/approval.wav", "darwin"), [
		{ command: "/usr/bin/afplay", args: ["/tmp/approval.wav"] },
	]);
});

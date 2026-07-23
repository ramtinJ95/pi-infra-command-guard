import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	autoNotificationBackend,
	customSoundProcesses,
	detectTerminalNotificationBackend,
	isHerdrPane,
	loadApprovalAttentionSettings,
	loadGuardSettings,
	loadPolicySettings,
	nativeNotificationProcesses,
	parseApprovalAttentionSettings,
	parseGuardSettings,
	parseCommandOverrides,
	parseHerdrNotificationOutput,
	sendTerminalNotification,
	shouldUseNativeNotification,
	terminalNotificationSequence,
} from "./attention.ts";
import { DEFAULT_COMMAND_OVERRIDES, DEFAULT_GUARD_SETTINGS } from "./guarded-executables.ts";
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

test("command override config validates and normalizes per-CLI rules", () => {
	const configPath = "/home/test/.pi/agent/infra-command-guard.json";
	assert.deepEqual(parseCommandOverrides({}, configPath), DEFAULT_COMMAND_OVERRIDES);
	assert.deepEqual(
		parseCommandOverrides(
			{
				commands: {
					kubectl: {
						allow: ["  delete   pod   dev-*  "],
						requireApproval: ["logs"],
					},
				},
			},
			configPath,
		).kubectl,
		{ allow: ["delete pod dev-*"], requireApproval: ["logs"] },
	);
	assert.throws(() => parseCommandOverrides({ commands: [] }, configPath), /commands must be a JSON object/);
	assert.throws(() => parseCommandOverrides({ commands: { azure: {} } }, configPath), /unknown field: azure/);
	assert.throws(() => parseCommandOverrides({ commands: { aws: { deny: [] } } }, configPath), /unknown field: deny/);
	assert.throws(() => parseCommandOverrides({ commands: { aws: { allow: "list" } } }, configPath), /array of strings/);
	assert.throws(() => parseCommandOverrides({ commands: { aws: { allow: [""] } } }, configPath), /must not be empty/);
	assert.throws(() => parseCommandOverrides({ commands: { aws: { allow: [12] } } }, configPath), /must be a string/);
	assert.throws(() => parseCommandOverrides({ commands: { aws: { allow: ["** *"] } } }, configPath), /literal character/);
	assert.deepEqual(parseCommandOverrides({ commands: { aws: { requireApproval: ["*"] } } }, configPath).aws, {
		allow: [],
		requireApproval: ["*"],
	});
	assert.throws(
		() => parseCommandOverrides({ commands: { aws: { allow: [`list${" ".repeat(509)}`] } } }, configPath),
		/cannot exceed 512 characters/,
	);
});

test("guard config defaults to enabled, accepts partial overrides, and reloads from disk", () => {
	const configPath = "/home/test/.pi/agent/infra-command-guard.json";
	assert.deepEqual(parseGuardSettings({}, configPath), DEFAULT_GUARD_SETTINGS);
	assert.deepEqual(parseGuardSettings({ guards: { az: false, rm: false } }, configPath), {
		...DEFAULT_GUARD_SETTINGS,
		az: false,
		rm: false,
	});
	assert.throws(() => parseGuardSettings({ guards: [] }, configPath), /guards must be a JSON object/);
	assert.throws(() => parseGuardSettings({ guards: { azure: false } }, configPath), /unknown field: azure/);
	assert.throws(() => parseGuardSettings({ guards: { terraform: "off" } }, configPath), /must be true or false/);

	const directory = mkdtempSync(join(tmpdir(), "infra-command-guard-config-"));
	const runtimeConfigPath = join(directory, "infra-command-guard.json");
	try {
		writeFileSync(runtimeConfigPath, JSON.stringify({ guards: { terraform: false } }));
		assert.equal(loadGuardSettings(runtimeConfigPath).settings.terraform, false);
		writeFileSync(runtimeConfigPath, JSON.stringify({ guards: { terraform: true } }));
		assert.equal(loadGuardSettings(runtimeConfigPath).settings.terraform, true);
		writeFileSync(runtimeConfigPath, JSON.stringify({ commands: { terraform: { allow: ["output"] } } }));
		assert.deepEqual(loadPolicySettings(runtimeConfigPath).settings.commands.terraform.allow, ["output"]);

		writeFileSync(runtimeConfigPath, JSON.stringify({ guards: { terraform: "off" } }));
		const invalid = loadGuardSettings(runtimeConfigPath);
		assert.match(invalid.error ?? "", /guards\.terraform must be true or false/);
		assert.deepEqual(invalid.settings, DEFAULT_GUARD_SETTINGS);
	} finally {
		rmSync(directory, { recursive: true, force: true });
	}
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
	const title = 'Title "quoted"; do shell script "false"';
	const body = "Body 'quoted'; Write-Error injected";
	const macos = nativeNotificationProcesses("darwin", title, body)[0]!;
	assert.deepEqual(macos.args.slice(-3), ["--", title, body]);
	assert.doesNotMatch(macos.args[1]!, /do shell script|Write-Error/);
	assert.doesNotMatch(macos.args.join(" "), /sound name/);

	const windows = nativeNotificationProcesses("win32", title, body)[0]!;
	assert.doesNotMatch(windows.args.join(" "), /Title "quoted"|Write-Error injected|SystemSounds/);
	assert.equal(windows.env?.PI_INFRA_COMMAND_GUARD_INTERNAL_NOTIFICATION_TITLE, title);
	assert.equal(windows.env?.PI_INFRA_COMMAND_GUARD_INTERNAL_NOTIFICATION_BODY, body);

	assert.deepEqual(customSoundProcesses("/tmp/approval.wav", "darwin"), [
		{ command: "/usr/bin/afplay", args: ["/tmp/approval.wav"] },
	]);
	const windowsSound = customSoundProcesses("C:\\Sounds\\approval's.wav", "win32")[0]!;
	assert.doesNotMatch(windowsSound.args.join(" "), /approval's\.wav/);
	assert.equal(windowsSound.env?.PI_INFRA_COMMAND_GUARD_INTERNAL_SOUND_PATH, "C:\\Sounds\\approval's.wav");
});

import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { getAgentDir, type ExtensionContext } from "@earendil-works/pi-coding-agent";
import {
	DEFAULT_GUARD_SETTINGS,
	GUARDED_EXECUTABLES,
	type GuardSettings,
} from "./guarded-executables.ts";

const CONFIG_FILE_NAME = "infra-command-guard.json";

type AttentionProcess = { command: string; args: string[]; env?: NodeJS.ProcessEnv };
type NotificationBackend = "auto" | "native" | "terminal";
type TerminalNotificationBackend = "kitty" | "ghostty";
type AttentionContext = Pick<ExtensionContext, "ui"> | undefined;
type ApprovalAttentionSettings = {
	notifications: { enabled: boolean; backend: NotificationBackend };
	sound: { enabled: boolean; path: string | null };
	integrations: { herdr: { enabled: boolean } };
};
type InfraCommandGuardSettings = ApprovalAttentionSettings & { guards: GuardSettings };

const DEFAULT_ATTENTION_SETTINGS: ApprovalAttentionSettings = {
	notifications: { enabled: false, backend: "auto" },
	sound: { enabled: false, path: null },
	integrations: { herdr: { enabled: true } },
};
const DEFAULT_SETTINGS: InfraCommandGuardSettings = {
	...DEFAULT_ATTENTION_SETTINGS,
	guards: DEFAULT_GUARD_SETTINGS,
};

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function assertKnownKeys(value: Record<string, unknown>, allowed: string[], label: string): void {
	const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
	if (unknown.length > 0) throw new Error(`${label} contains unknown field${unknown.length === 1 ? "" : "s"}: ${unknown.join(", ")}`);
}

function expandConfigPath(path: string, configPath: string): string {
	if (path === "~") return homedir();
	if (path.startsWith("~/") || path.startsWith("~\\")) return join(homedir(), path.slice(2));
	return isAbsolute(path) ? path : resolve(dirname(configPath), path);
}

function parseSettings(value: unknown, configPath: string): InfraCommandGuardSettings {
	if (!isRecord(value)) throw new Error("configuration root must be a JSON object");
	assertKnownKeys(value, ["$schema", "guards", "notifications", "sound", "integrations"], "configuration root");

	let guards: GuardSettings = DEFAULT_GUARD_SETTINGS;
	const settings: InfraCommandGuardSettings = {
		notifications: { ...DEFAULT_ATTENTION_SETTINGS.notifications },
		sound: { ...DEFAULT_ATTENTION_SETTINGS.sound },
		integrations: { herdr: { ...DEFAULT_ATTENTION_SETTINGS.integrations.herdr } },
		guards,
	};

	if (value.guards !== undefined) {
		if (!isRecord(value.guards)) throw new Error("guards must be a JSON object");
		assertKnownKeys(value.guards, [...GUARDED_EXECUTABLES], "guards");
		const configuredGuards = { ...DEFAULT_GUARD_SETTINGS } as Record<(typeof GUARDED_EXECUTABLES)[number], boolean>;
		for (const executable of GUARDED_EXECUTABLES) {
			const configured = value.guards[executable];
			if (configured !== undefined && typeof configured !== "boolean") {
				throw new Error(`guards.${executable} must be true or false`);
			}
			configuredGuards[executable] = configured ?? configuredGuards[executable];
		}
		guards = configuredGuards;
		settings.guards = guards;
	}

	if (value.notifications !== undefined) {
		if (!isRecord(value.notifications)) throw new Error("notifications must be a JSON object");
		assertKnownKeys(value.notifications, ["enabled", "backend"], "notifications");
		if (value.notifications.enabled !== undefined && typeof value.notifications.enabled !== "boolean") {
			throw new Error("notifications.enabled must be true or false");
		}
		if (
			value.notifications.backend !== undefined &&
			!(["auto", "native", "terminal"] as unknown[]).includes(value.notifications.backend)
		) {
			throw new Error('notifications.backend must be "auto", "native", or "terminal"');
		}
		settings.notifications.enabled = value.notifications.enabled ?? settings.notifications.enabled;
		settings.notifications.backend =
			(value.notifications.backend as NotificationBackend | undefined) ?? settings.notifications.backend;
	}

	if (value.sound !== undefined) {
		if (!isRecord(value.sound)) throw new Error("sound must be a JSON object");
		assertKnownKeys(value.sound, ["enabled", "path"], "sound");
		if (value.sound.enabled !== undefined && typeof value.sound.enabled !== "boolean") {
			throw new Error("sound.enabled must be true or false");
		}
		if (value.sound.path !== undefined && value.sound.path !== null && typeof value.sound.path !== "string") {
			throw new Error("sound.path must be a string or null");
		}
		settings.sound.enabled = value.sound.enabled ?? settings.sound.enabled;
		const configuredPath = typeof value.sound.path === "string" ? value.sound.path.trim() : value.sound.path;
		settings.sound.path = configuredPath ? expandConfigPath(configuredPath, configPath) : null;
		if (settings.sound.enabled && !settings.sound.path) {
			throw new Error("sound.path must be set when sound.enabled is true");
		}
	}

	if (value.integrations !== undefined) {
		if (!isRecord(value.integrations)) throw new Error("integrations must be a JSON object");
		assertKnownKeys(value.integrations, ["herdr"], "integrations");
		if (value.integrations.herdr !== undefined) {
			if (!isRecord(value.integrations.herdr)) throw new Error("integrations.herdr must be a JSON object");
			assertKnownKeys(value.integrations.herdr, ["enabled"], "integrations.herdr");
			if (value.integrations.herdr.enabled !== undefined && typeof value.integrations.herdr.enabled !== "boolean") {
				throw new Error("integrations.herdr.enabled must be true or false");
			}
			settings.integrations.herdr.enabled =
				value.integrations.herdr.enabled ?? settings.integrations.herdr.enabled;
		}
	}

	return settings;
}

function parseApprovalAttentionSettings(value: unknown, configPath: string): ApprovalAttentionSettings {
	const { guards: _guards, ...attention } = parseSettings(value, configPath);
	return attention;
}

function parseGuardSettings(value: unknown, configPath: string): GuardSettings {
	return parseSettings(value, configPath).guards;
}

function loadSettings(configPath = join(getAgentDir(), CONFIG_FILE_NAME)): {
	configPath: string;
	settings: InfraCommandGuardSettings;
	error?: string;
} {
	try {
		const source = readFileSync(configPath, "utf8");
		return { configPath, settings: parseSettings(JSON.parse(source), configPath) };
	} catch (error: unknown) {
		if (error instanceof Error && "code" in error && error.code === "ENOENT") {
			return { configPath, settings: DEFAULT_SETTINGS };
		}
		return {
			configPath,
			settings: DEFAULT_SETTINGS,
			error: error instanceof Error ? error.message : String(error),
		};
	}
}

function loadApprovalAttentionSettings(configPath = join(getAgentDir(), CONFIG_FILE_NAME)): {
	configPath: string;
	settings: ApprovalAttentionSettings;
	error?: string;
} {
	const loaded = loadSettings(configPath);
	const { guards: _guards, ...settings } = loaded.settings;
	return { configPath: loaded.configPath, settings, ...(loaded.error ? { error: loaded.error } : {}) };
}

function loadGuardSettings(configPath = join(getAgentDir(), CONFIG_FILE_NAME)): {
	configPath: string;
	settings: GuardSettings;
	error?: string;
} {
	const loaded = loadSettings(configPath);
	return {
		configPath: loaded.configPath,
		settings: loaded.settings.guards,
		...(loaded.error ? { error: loaded.error } : {}),
	};
}

function notifyAttentionFailure(ctx: AttentionContext, label: string): void {
	try {
		ctx?.ui?.notify?.(`infra-command-guard could not ${label}; the approval overlay is still active.`, "warning");
	} catch {}
}

function runAttentionProcess(candidates: AttentionProcess[], ctx: AttentionContext, label: string, index = 0): void {
	const candidate = candidates[index];
	if (!candidate) {
		notifyAttentionFailure(ctx, label);
		return;
	}

	let settled = false;
	try {
		const child = spawn(candidate.command, candidate.args, {
			stdio: "ignore",
			env: candidate.env ? { ...process.env, ...candidate.env } : undefined,
		});
		const tryNext = () => {
			if (settled) return;
			settled = true;
			runAttentionProcess(candidates, ctx, label, index + 1);
		};
		child.once("error", tryNext);
		child.once("exit", (code) => {
			if (code !== 0) tryNext();
		});
	} catch {
		runAttentionProcess(candidates, ctx, label, index + 1);
	}
}

function customSoundProcesses(path: string, platform: NodeJS.Platform = process.platform): AttentionProcess[] {
	if (platform === "darwin") return [{ command: "/usr/bin/afplay", args: [path] }];
	if (platform === "linux") {
		return [
			{ command: "paplay", args: [path] },
			{ command: "aplay", args: [path] },
		];
	}
	if (platform === "win32") {
		return [
			{
				command: "powershell.exe",
				args: [
					"-NoProfile",
					"-NonInteractive",
					"-Command",
					"(New-Object System.Media.SoundPlayer($env:PI_INFRA_COMMAND_GUARD_INTERNAL_SOUND_PATH)).PlaySync()",
				],
				env: { PI_INFRA_COMMAND_GUARD_INTERNAL_SOUND_PATH: path },
			},
		];
	}
	return [];
}

function nativeNotificationProcesses(
	platform: NodeJS.Platform = process.platform,
	title = "Pi infrastructure guard",
	body = "A command requires approval in Pi.",
): AttentionProcess[] {
	if (platform === "darwin") {
		return [
			{
				command: "/usr/bin/osascript",
				args: [
					"-e",
					"on run argv\n  display notification (item 2 of argv) with title (item 1 of argv)\nend run",
					"--",
					title,
					body,
				],
			},
		];
	}
	if (platform === "linux") {
		return [{ command: "notify-send", args: ["--urgency=critical", title, body] }];
	}
	if (platform === "win32") {
		return [
			{
				command: "powershell.exe",
				args: [
					"-NoProfile",
					"-NonInteractive",
					"-Command",
					"Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; $n = New-Object System.Windows.Forms.NotifyIcon; $n.Icon = [System.Drawing.SystemIcons]::Warning; $n.Visible = $true; $n.ShowBalloonTip(5000, $env:PI_INFRA_COMMAND_GUARD_INTERNAL_NOTIFICATION_TITLE, $env:PI_INFRA_COMMAND_GUARD_INTERNAL_NOTIFICATION_BODY, 'Warning'); Start-Sleep -Seconds 6; $n.Dispose()",
				],
				env: {
					PI_INFRA_COMMAND_GUARD_INTERNAL_NOTIFICATION_TITLE: title,
					PI_INFRA_COMMAND_GUARD_INTERNAL_NOTIFICATION_BODY: body,
				},
			},
		];
	}
	return [];
}

function detectTerminalNotificationBackend(env: NodeJS.ProcessEnv = process.env): TerminalNotificationBackend | undefined {
	const term = env.TERM?.toLowerCase() ?? "";
	const termProgram = env.TERM_PROGRAM?.toLowerCase() ?? "";
	if (env.KITTY_WINDOW_ID || term === "xterm-kitty") return "kitty";
	if (env.GHOSTTY_RESOURCES_DIR || termProgram === "ghostty" || term.includes("ghostty")) return "ghostty";
	return undefined;
}

function autoNotificationBackend(platform: NodeJS.Platform = process.platform): "native" | "terminal" {
	return platform === "darwin" || platform === "win32" ? "native" : "terminal";
}

function isHerdrPane(env: NodeJS.ProcessEnv = process.env): boolean {
	return env.HERDR_ENV === "1" && Boolean(env.HERDR_SOCKET_PATH);
}

function shouldUseNativeNotification(
	settings: ApprovalAttentionSettings,
	platform: NodeJS.Platform = process.platform,
	env: NodeJS.ProcessEnv = process.env,
): boolean {
	if (settings.notifications.backend === "native") return true;
	if (settings.notifications.backend !== "auto") return false;
	return autoNotificationBackend(platform) === "native" || (settings.integrations.herdr.enabled && isHerdrPane(env));
}

type HerdrNotificationResult = { shown: boolean; reason: string };

function parseHerdrNotificationOutput(source: string): HerdrNotificationResult {
	try {
		const value = JSON.parse(source);
		const result = isRecord(value) && isRecord(value.result) ? value.result : undefined;
		if (result && typeof result.shown === "boolean" && typeof result.reason === "string") {
			return { shown: result.shown, reason: result.reason };
		}
	} catch {}
	return { shown: false, reason: "invalid response" };
}

function requestHerdrNotification(title: string, body: string, timeoutMs = 1500): Promise<HerdrNotificationResult> {
	return new Promise((resolveResult) => {
		let settled = false;
		let stdout = "";
		const settle = (result: HerdrNotificationResult) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolveResult(result);
		};

		let child: ReturnType<typeof spawn>;
		try {
			child = spawn("herdr", ["notification", "show", title, "--body", body, "--sound", "none"], {
				stdio: ["ignore", "pipe", "pipe"],
			});
		} catch {
			resolveResult({ shown: false, reason: "could not start herdr" });
			return;
		}

		const timer = setTimeout(() => {
			child.kill();
			settle({ shown: false, reason: "timed out" });
		}, timeoutMs);
		child.stdout?.on("data", (chunk) => {
			if (stdout.length < 64 * 1024) stdout += String(chunk);
		});
		child.stderr?.resume();
		child.once("error", () => settle({ shown: false, reason: "could not start herdr" }));
		child.once("close", (code) => {
			if (code !== 0) {
				settle({ shown: false, reason: `herdr exited with status ${code ?? "unknown"}` });
				return;
			}
			settle(parseHerdrNotificationOutput(stdout));
		});
	});
}

function terminalNotificationSequence(backend: TerminalNotificationBackend, title: string, body: string): string {
	if (backend === "kitty") {
		const id = "pi-infra-command-guard";
		const encodedAppName = Buffer.from("pi-infra-command-guard", "utf8").toString("base64");
		const encodedSound = Buffer.from("silent", "utf8").toString("base64");
		const encodedTitle = Buffer.from(title, "utf8").toString("base64");
		const encodedBody = Buffer.from(body, "utf8").toString("base64");
		return (
			`\u001b]99;i=${id}:d=0:f=${encodedAppName}:s=${encodedSound};\u001b\\` +
			`\u001b]99;i=${id}:d=0:e=1;${encodedTitle}\u001b\\` +
			`\u001b]99;i=${id}:d=0:e=1:p=body;${encodedBody}\u001b\\` +
			`\u001b]99;i=${id};\u001b\\`
		);
	}

	const message = `${title}: ${body}`.replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, 1024);
	return `\u001b]9;${message}\u001b\\`;
}

function sendTerminalNotification(
	backend: TerminalNotificationBackend,
	title: string,
	body: string,
	output: Pick<NodeJS.WriteStream, "isTTY" | "write"> = process.stdout,
): boolean {
	if (!output.isTTY) return false;
	try {
		output.write(terminalNotificationSequence(backend, title, body));
		return true;
	} catch {
		return false;
	}
}

async function requestApprovalAttention(
	ctx: AttentionContext,
	title = "Pi infrastructure guard",
	body = "A command requires approval in Pi.",
): Promise<string> {
	const loaded = loadApprovalAttentionSettings();
	if (loaded.error) {
		try {
			ctx?.ui?.notify?.(`infra-command-guard could not read ${loaded.configPath}: ${loaded.error}. Notifications are disabled.`, "warning");
		} catch {}
		return `configuration error in ${loaded.configPath}`;
	}

	const { settings } = loaded;
	if (settings.sound.enabled && settings.sound.path) {
		runAttentionProcess(customSoundProcesses(settings.sound.path), ctx, "play the configured approval sound");
	}

	if (!settings.notifications.enabled) return settings.sound.enabled ? "custom sound only" : "disabled";
	if (shouldUseNativeNotification(settings)) {
		runAttentionProcess(nativeNotificationProcesses(process.platform, title, body), ctx, "show a native approval notification");
		return `native notification (${process.platform})`;
	}

	if (
		settings.integrations.herdr.enabled &&
		settings.notifications.backend === "terminal" &&
		isHerdrPane()
	) {
		const result = await requestHerdrNotification(title, body);
		if (result.shown) return "Herdr notification broker";
		notifyAttentionFailure(ctx, `deliver through Herdr (${result.reason})`);
		return `Herdr notification failed (${result.reason})`;
	}

	const terminalBackend = detectTerminalNotificationBackend();
	if (terminalBackend && sendTerminalNotification(terminalBackend, title, body)) {
		return `${terminalBackend} terminal notification`;
	}

	if (settings.notifications.backend === "terminal") {
		notifyAttentionFailure(ctx, terminalBackend ? "send a terminal approval notification" : "detect a supported terminal notifier");
		return terminalBackend ? `${terminalBackend} terminal notification failed` : "no supported terminal detected";
	}

	runAttentionProcess(nativeNotificationProcesses(process.platform, title, body), ctx, "show a native approval notification");
	return `native notification fallback (${process.platform})`;
}

export {
	parseApprovalAttentionSettings,
	parseGuardSettings,
	loadApprovalAttentionSettings,
	loadGuardSettings,
	detectTerminalNotificationBackend,
	autoNotificationBackend,
	isHerdrPane,
	shouldUseNativeNotification,
	parseHerdrNotificationOutput,
	terminalNotificationSequence,
	sendTerminalNotification,
	customSoundProcesses,
	nativeNotificationProcesses,
	requestApprovalAttention,
};

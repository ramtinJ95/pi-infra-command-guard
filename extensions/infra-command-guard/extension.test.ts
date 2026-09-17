import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	APPROVAL_STORE_KEY,
	BYPASS_STORE_KEY,
	ApprovalStore,
	executionIdentity,
} from "./approvals.ts";
import type { GuardBypassStore } from "./bypass.ts";
import {
	type CodeModeToolCall,
	type CodeModeToolPreflight,
} from "./code-mode.ts";
import createExtension from "./index.ts";
import { test } from "./test-harness.ts";
import {
	REVIEW_VERDICTS,
	TYPESAFE_MODEL,
	TYPESAFE_STORE_KEY,
	type ReviewTransport,
	type ReviewVerdict,
	type TypeSafeReviewStore,
} from "./typesafe.ts";

const ALL_GUARDS_DISABLED = {
	argocd: false,
	aws: false,
	az: false,
	docker: false,
	git: false,
	vault: false,
	find: false,
	gcloud: false,
	helm: false,
	kubectl: false,
	rm: false,
	rmdir: false,
	rsync: false,
	shred: false,
	terraform: false,
	truncate: false,
	unlink: false,
};

const PREFLIGHT_PROTOCOL =
	"@howaboua/pi-codex-conversion/code-mode-preflight/v1";
const PREFLIGHT_REQUEST_CHANNEL = `${PREFLIGHT_PROTOCOL}/request`;
const PREFLIGHT_AVAILABLE_CHANNEL = `${PREFLIGHT_PROTOCOL}/available`;

function createTestEventBus() {
	const listeners = new Map<string, Set<(data: unknown) => void>>();
	return {
		facade() {
			return {
				emit(channel: string, data: unknown) {
					for (const handler of [...(listeners.get(channel) ?? [])]) handler(data);
				},
				on(channel: string, handler: (data: unknown) => void) {
					const handlers = listeners.get(channel) ?? new Set();
					handlers.add(handler);
					listeners.set(channel, handlers);
					return () => handlers.delete(handler);
				},
			};
		},
	};
}

type EventFacade = ReturnType<ReturnType<typeof createTestEventBus>["facade"]>;

function createHarness(events: EventFacade, dependencies?: Parameters<typeof createExtension>[1]) {
	const handlers = new Map<string, Array<(event: any, context: any) => unknown>>();
	const tools: any[] = [];
	const commands = new Map<string, { handler(args: string, context: any): unknown }>();
	const pi = {
		events,
		registerCommand(name: string, command: { handler(args: string, context: any): unknown }) {
			commands.set(name, command);
		},
		registerTool(tool: any) { tools.push(tool); },
		on(name: string, handler: (event: any, context: any) => unknown) {
			handlers.set(name, [...(handlers.get(name) ?? []), handler]);
		},
	};
	createExtension(pi as never, dependencies);
	return { commands, handlers, pi, tools };
}

type RecordedTypeSafeCall = { url: string; init: RequestInit; body: any };

function judgedTypeSafeBody(verdict: ReviewVerdict, confidence = 0.8): unknown {
	const rest = (1 - confidence) / (REVIEW_VERDICTS.length - 1);
	return {
		model: TYPESAFE_MODEL,
		answers: {
			reason_match: {
				type: "choice",
				choice: verdict,
				confidence,
				probabilities: Object.fromEntries(REVIEW_VERDICTS.map((candidate) => [candidate, candidate === verdict ? confidence : rest])),
			},
		},
		usage: { input_tokens: 1, output_tokens: 1 },
	};
}

function createTypeSafeTransport(
	respond: (call: RecordedTypeSafeCall, signal: AbortSignal | null | undefined) => Promise<Response> | Response,
	env: NodeJS.ProcessEnv = { TYPESAFE_API_KEY: "test-key" },
): ReviewTransport & { calls: RecordedTypeSafeCall[] } {
	const calls: RecordedTypeSafeCall[] = [];
	return {
		calls,
		env,
		fetch: (async (input: string | URL | Request, init?: RequestInit) => {
			const call = { url: String(input), init: init ?? {}, body: init?.body ? JSON.parse(String(init.body)) : undefined };
			calls.push(call);
			return respond(call, init?.signal);
		}) as typeof fetch,
	};
}

function jsonTypeSafeResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function withAgentDir<T>(prefix: string, run: (directory: string, configPath: string) => Promise<T>): Promise<T> {
	const directory = mkdtempSync(join(tmpdir(), prefix));
	const previousAgentDir = process.env.PI_CODING_AGENT_DIR;
	process.env.PI_CODING_AGENT_DIR = directory;
	return run(directory, join(directory, "infra-command-guard.json")).finally(() => {
		if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
		else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
		rmSync(directory, { recursive: true, force: true });
	});
}

// Drives a blocked command through the approval tool, capturing the rendered
// overlay so tests can assert what the user actually sees.
async function approveBlocked(
	harness: ReturnType<typeof createHarness>,
	cmd: string,
	key: "y" | "n",
	options: { cwd?: string; notifications?: string[]; statuses?: Array<string | undefined> } = {},
) {
	const cwd = options.cwd ?? "/tmp";
	const context = {
		cwd,
		mode: "tui",
		ui: {
			notify(message: string) { options.notifications?.push(message); },
			setStatus(_key: string, value: string | undefined) { options.statuses?.push(value); },
		},
	};
	const toolCall = harness.handlers.get("tool_call")![0]!;
	const blocked = await toolCall({ toolName: "exec_command", input: { cmd } }, context) as { block: boolean; reason: string } | undefined;
	assert.ok(blocked?.block, `expected ${cmd} to be blocked`);
	const requestId = blocked.reason.match(/Approval request: ([^\n]+)/)?.[1];
	const reason = blocked.reason.match(/^BLOCKED — ([^\n]+)/)?.[1];
	assert.ok(requestId && reason, blocked.reason);
	const theme = { fg: (_color: string, text: string) => text, bold: (text: string) => text, bg: (_color: string, text: string) => text };
	let rendered = "";
	const approve = harness.tools.find((tool) => tool.name === "approve_infra_command")!;
	const result = await approve.execute(
		"approve",
		{ request_id: requestId, command: cmd, reason, summary: "summary", flags: [], blastRadius: "blast radius" },
		new AbortController().signal,
		undefined,
		{
			...context,
			ui: {
				...context.ui,
				async custom(factory: (...args: any[]) => { render(width: number): string[]; handleInput(data: string): void }) {
					let choice = "cancel";
					const overlay = factory({ requestRender() {}, terminal: { rows: 80 } }, theme, { matches: () => false }, (selected: string) => { choice = selected; });
					rendered = overlay.render(160).join("\n").replace(/[│╭╮╰╯─]/g, " ").replace(/\s+/g, " ");
					overlay.handleInput(key);
					return choice;
				},
				async select() { return undefined; },
			},
		},
	);
	return { result, rendered, reason, requestId, context };
}

function createPreflightBroker(events: EventFacade) {
	const handlers = new Set<CodeModeToolPreflight>();
	let active = true;
	const broker = {
		protocol: PREFLIGHT_PROTOCOL,
		isActive: () => active,
		register(handler: CodeModeToolPreflight) {
			handlers.add(handler);
			return () => handlers.delete(handler);
		},
	};
	const stopRequests = events.on(PREFLIGHT_REQUEST_CHANNEL, (request) => {
		if (
			request &&
			typeof request === "object" &&
			"protocol" in request &&
			request.protocol === PREFLIGHT_PROTOCOL
		) events.emit(PREFLIGHT_AVAILABLE_CHANNEL, broker);
	});
	events.emit(PREFLIGHT_AVAILABLE_CHANNEL, broker);
	return {
		handlers,
		shutdown() {
			active = false;
			handlers.clear();
			stopRequests();
		},
	};
}

async function waitForPreflight(broker: ReturnType<typeof createPreflightBroker>) {
	for (let attempt = 0; attempt < 20 && broker.handlers.size === 0; attempt += 1) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
	assert.equal(broker.handlers.size, 1);
	return [...broker.handlers][0]!;
}

function nestedCall(cmd: string): CodeModeToolCall {
	return {
		toolName: "exec_command",
		toolCallId: "nested-exec",
		input: { cmd },
		cwd: "/tmp",
		extensionContext: { cwd: "/tmp", mode: "tui" } as never,
		signal: new AbortController().signal,
	};
}

test("outer Code Mode calls fail closed when nested preflights are unavailable", async () => {
	const events = createTestEventBus().facade();
	const { handlers } = createHarness(events);
	const toolCall = handlers.get("tool_call")![0]!;
	for (const toolName of ["exec", "wait", "functions.exec", "functions.wait"]) {
		const decision = await toolCall({ toolName, input: {} }, { cwd: "/tmp", mode: "tui" });
		assert.deepEqual(decision, {
			block: true,
			reason: "BLOCKED — infra-command-guard cannot safely intercept Code Mode because its nested-tool preflight API is unavailable. Update pi-codex-conversion or disable Code Mode before running commands.",
		});
	}
});

test("infra-guard menu pauses, resumes, and removes individual bypasses without inert rows", async () => {
	const directory = mkdtempSync(join(tmpdir(), "infra-command-guard-menu-"));
	const previousAgentDir = process.env.PI_CODING_AGENT_DIR;
	process.env.PI_CODING_AGENT_DIR = directory;
	try {
		const events = createTestEventBus().facade();
		const { commands, handlers, pi } = createHarness(events);
		const command = commands.get("infra-guard")!;
		const toolCall = handlers.get("tool_call")![0]!;
		const bypasses = (pi.events as unknown as Record<PropertyKey, unknown>)[BYPASS_STORE_KEY] as GuardBypassStore;
		const approvals = (pi.events as unknown as Record<PropertyKey, unknown>)[APPROVAL_STORE_KEY] as ApprovalStore;
		const notifications: string[] = [];
		const statuses: Array<string | undefined> = [];
		const runMenu = async (
			selections: string[],
			inspect?: (title: string, options: string[]) => void,
		) => {
			let index = 0;
			await command.handler("", {
				hasUI: true,
				mode: "tui",
				ui: {
					async select(title: string, options: string[]) {
						inspect?.(title, options);
						return selections[index++];
					},
					notify(message: string) { notifications.push(message); },
					setStatus(_name: string, value: string | undefined) { statuses.push(value); },
				},
			});
		};

		const stalePending = approvals.createPending(
			executionIdentity("exec-command", { cmd: "rm stale-menu-request" }, "/tmp")!,
			"rm command needs confirmation",
		);
		await runMenu(["Pause guard…", "10 minutes"], (_title, options) => {
			if (options.includes("Pause guard…")) assert.deepEqual(options, ["Pause guard…"]);
		});
		assert.equal(bypasses.isPaused(), true);
		assert.equal(
			approvals.validate(stalePending.id, "rm stale-menu-request", "rm command needs confirmation").ok,
			false,
		);
		assert.equal(
			await toolCall({ toolName: "exec_command", input: { cmd: "rm paused-menu-target" } }, { cwd: "/tmp", mode: "tui" }),
			undefined,
		);

		await runMenu(["Resume guard now"]);
		assert.equal(bypasses.isPaused(), false);
		const blocked = await toolCall(
			{ toolName: "exec_command", input: { cmd: "rm resumed-menu-target" } },
			{ cwd: "/tmp", mode: "tui" },
		) as { block: boolean };
		assert.equal(blocked.block, true);

		bypasses.addRule("kubectl", "/repo", { kind: "command-prefix", tokens: ["delete pod", "api"] }, 10 * 60 * 1000);
		bypasses.addRule("kubectl", "/repo", { kind: "command-prefix", tokens: ["delete", "pod api"] }, 10 * 60 * 1000);
		const [firstRule, secondRule] = bypasses.listRules();
		assert.ok(firstRule);
		assert.ok(secondRule);
		assert.equal(bypasses.describeRule(firstRule), bypasses.describeRule(secondRule));
		const firstRemoveOption = `Remove bypass 1: ${bypasses.describeRule(firstRule)}`;
		const secondRemoveOption = `Remove bypass 2: ${bypasses.describeRule(secondRule)}`;
		await runMenu([secondRemoveOption], (_title, options) => {
			assert.deepEqual(options, [
				"Pause guard…",
				firstRemoveOption,
				secondRemoveOption,
				"Clear all pauses and bypasses",
			]);
		});
		assert.deepEqual(bypasses.listRules(), [firstRule]);
		await runMenu([firstRemoveOption]);
		assert.deepEqual(bypasses.listRules(), []);
		assert.match(notifications.at(-1) ?? "", /Removed bypass/);
		assert.ok(statuses.length > 0);
	} finally {
		if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
		else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
		rmSync(directory, { recursive: true, force: true });
	}
});

test("approval-overlay bypass keeps the blocked command cwd and does not leave a one-time grant", async () => {
	const directory = mkdtempSync(join(tmpdir(), "infra-command-guard-bypass-flow-"));
	const previousAgentDir = process.env.PI_CODING_AGENT_DIR;
	process.env.PI_CODING_AGENT_DIR = directory;
	try {
		const events = createTestEventBus().facade();
		const { handlers, pi, tools } = createHarness(events);
		const toolCall = handlers.get("tool_call")![0]!;
		const command = "kubectl --kubeconfig /tmp/kc delete pod api";
		const blocked = await toolCall(
			{ toolName: "exec_command", input: { cmd: command, workdir: "nested" } },
			{ cwd: "/repo", mode: "tui" },
		) as { block: boolean; reason: string };
		assert.equal(blocked.block, true);
		const requestId = blocked.reason.match(/Approval request: ([^\n]+)/)?.[1];
		const reason = blocked.reason.match(/^BLOCKED — ([^\n]+)/)?.[1];
		assert.ok(requestId);
		assert.ok(reason);

		const approve = tools.find((tool) => tool.name === "approve_infra_command")!;
		const result = await approve.execute(
			"approve-bypass",
			{
				request_id: requestId,
				command,
				reason,
				summary: "Delete one test pod.",
				flags: [],
				blastRadius: "The named pod is removed.",
			},
			new AbortController().signal,
			undefined,
			{
				cwd: "/different-approval-tool-cwd",
				mode: "tui",
				ui: {
					async custom(factory: (...args: any[]) => { handleInput(data: string): void }) {
						let choice = "cancel";
						const overlay = factory(
							{ requestRender() {} },
							{},
							{ matches: () => false },
							(selected: string) => { choice = selected; },
						);
						overlay.handleInput("b");
						return choice;
					},
					async select() { return "10 minutes"; },
					notify() {},
					setStatus() {},
				},
			},
		);
		assert.equal(result.details.approved, true);
		assert.equal(result.details.bypass, true);
		assert.match(result.content[0].text, /Bypass active/);

		const bypasses = (pi.events as unknown as Record<PropertyKey, unknown>)[BYPASS_STORE_KEY] as GuardBypassStore;
		const approvals = (pi.events as unknown as Record<PropertyKey, unknown>)[APPROVAL_STORE_KEY] as ApprovalStore;
		const [rule] = bypasses.listRules();
		assert.ok(rule);
		assert.equal(rule.cwd, "/repo/nested");
		assert.deepEqual(rule.scope, { kind: "kubectl-kubeconfig", path: "/tmp/kc" });
		assert.equal(
			approvals.consume(executionIdentity("exec-command", { cmd: command, workdir: "nested" }, "/repo")!),
			false,
			"a scoped bypass must not leave an unused one-time approval",
		);
		assert.equal(
			await toolCall(
				{ toolName: "exec_command", input: { cmd: command, workdir: "nested" } },
				{ cwd: "/repo", mode: "tui" },
			),
			undefined,
		);
		assert.equal(
			await toolCall(
				{
					toolName: "exec_command",
					input: { cmd: "kubectl rollout restart deployment/api --kubeconfig=/tmp/kc", workdir: "nested" },
				},
				{ cwd: "/repo", mode: "tui" },
			),
			undefined,
			"the approved kubeconfig covers a different guarded kubectl operation in the same cwd",
		);
		const outside = await toolCall(
			{ toolName: "exec_command", input: { cmd: command } },
			{ cwd: "/different-approval-tool-cwd", mode: "tui" },
		) as { block: boolean };
		assert.equal(outside.block, true);
	} finally {
		if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
		else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
		rmSync(directory, { recursive: true, force: true });
	}
});

test("bypass creation revalidates pending authority after duration selection", async () => {
	const directory = mkdtempSync(join(tmpdir(), "infra-command-guard-stale-bypass-"));
	const previousAgentDir = process.env.PI_CODING_AGENT_DIR;
	process.env.PI_CODING_AGENT_DIR = directory;
	try {
		const events = createTestEventBus().facade();
		const { handlers, pi, tools } = createHarness(events);
		const command = "kubectl --kubeconfig /tmp/kc delete pod api";
		const blocked = await handlers.get("tool_call")![0]!(
			{ toolName: "exec_command", input: { cmd: command } },
			{ cwd: "/repo", mode: "tui" },
		) as { reason: string };
		const requestId = blocked.reason.match(/Approval request: ([^\n]+)/)?.[1];
		const reason = blocked.reason.match(/^BLOCKED — ([^\n]+)/)?.[1];
		assert.ok(requestId);
		assert.ok(reason);
		const approvals = (pi.events as unknown as Record<PropertyKey, unknown>)[APPROVAL_STORE_KEY] as ApprovalStore;
		const bypasses = (pi.events as unknown as Record<PropertyKey, unknown>)[BYPASS_STORE_KEY] as GuardBypassStore;
		const notifications: string[] = [];
		const approve = tools.find((tool) => tool.name === "approve_infra_command")!;
		const result = await approve.execute(
			"approve-stale-bypass",
			{
				request_id: requestId,
				command,
				reason,
				summary: "Delete one test pod.",
				flags: [],
				blastRadius: "The named pod is removed.",
			},
			new AbortController().signal,
			undefined,
			{
				cwd: "/repo",
				mode: "tui",
				ui: {
					async custom(factory: (...args: any[]) => { handleInput(data: string): void }) {
						let choice = "cancel";
						const overlay = factory(
							{ requestRender() {} },
							{},
							{ matches: () => false },
							(selected: string) => { choice = selected; },
						);
						overlay.handleInput("b");
						return choice;
					},
					async select() {
						approvals.clear();
						return "10 minutes";
					},
					notify(message: string) { notifications.push(message); },
					setStatus() {},
				},
			},
		);
		assert.equal(result.details.approved, false);
		assert.deepEqual(bypasses.listRules(), []);
		assert.match(notifications.at(-1) ?? "", /expired or changed/);
	} finally {
		if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
		else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
		rmSync(directory, { recursive: true, force: true });
	}
});

test("extension allows outer Code Mode calls only after its nested preflight connects", async () => {
	const bus = createTestEventBus();
	const broker = createPreflightBroker(bus.facade());
	const { handlers } = createHarness(bus.facade());
	const preflight = await waitForPreflight(broker);
	const toolCall = handlers.get("tool_call")![0]!;
	const context = { cwd: "/tmp", mode: "tui" };
	assert.equal(
		await toolCall({ toolName: "exec", input: { code: "dynamic" } }, context),
		undefined,
	);
	const blocked = await preflight(nestedCall("rm guarded-target"));
	assert.equal(blocked?.block, true);
	assert.match(blocked?.reason ?? "", /Approval request:/);
	assert.equal(
		await preflight({ ...nestedCall("ignored"), toolName: "apply_patch" }),
		undefined,
	);
	assert.equal(
		await preflight({
			...nestedCall("ignored"),
			toolName: "write_stdin",
			input: { session_id: 42, chars: "input\n" },
		}),
		undefined,
	);
	broker.shutdown();
});

test("Code Mode kubeconfig bypass covers kubectl operations but not another guarded invocation", async () => {
	const bus = createTestEventBus();
	const broker = createPreflightBroker(bus.facade());
	const { pi } = createHarness(bus.facade());
	const preflight = await waitForPreflight(broker);
	const bypasses = (pi.events as unknown as Record<PropertyKey, unknown>)[BYPASS_STORE_KEY] as GuardBypassStore;
	bypasses.addRule("kubectl", "/repo", { kind: "kubectl-kubeconfig", path: "/tmp/kc" }, 10 * 60 * 1000);
	const call = {
		...nestedCall("kubectl --kubeconfig /tmp/kc delete pod api"),
		cwd: "/repo",
		extensionContext: { cwd: "/repo", mode: "tui" } as never,
	};
	assert.equal(await preflight(call), undefined);
	assert.equal(
		await preflight({ ...call, input: { cmd: "kubectl rollout restart deployment/api --kubeconfig=/tmp/kc" } }),
		undefined,
	);
	const compound = await preflight({
		...call,
		input: { cmd: "kubectl --kubeconfig /tmp/kc delete pod api && rm other-target" },
	});
	assert.equal(compound?.block, true);
	assert.match(compound?.reason ?? "", /Approval request:/);
	broker.shutdown();
});

test("Code Mode preflight registrations switch safely across guard reloads", async () => {
	const bus = createTestEventBus();
	const broker = createPreflightBroker(bus.facade());
	const first = createHarness(bus.facade());
	await waitForPreflight(broker);
	for (const handler of first.handlers.get("session_shutdown") ?? []) await handler({}, {});
	assert.equal(broker.handlers.size, 0);

	const second = createHarness(bus.facade());
	const preflight = await waitForPreflight(broker);
	const blocked = await preflight(nestedCall("rm after-reload"));
	assert.equal(blocked?.block, true);
	assert.match(blocked?.reason ?? "", /Approval request:/);
	for (const handler of second.handlers.get("session_shutdown") ?? []) await handler({}, {});
	broker.shutdown();
});

test("approval requests do not leak across Pi 0.84 extension instances", async () => {
	const bus = createTestEventBus();
	const first = createHarness(bus.facade());
	const firstToolCall = first.handlers.get("tool_call")![0]!;
	const blocked = await firstToolCall(
		{ toolName: "exec_command", input: { cmd: "rm old-instance" } },
		{ cwd: "/tmp", mode: "tui" },
	) as { reason: string };
	const requestId = blocked.reason.match(/Approval request: ([0-9a-f-]+)/)?.[1];
	assert.ok(requestId);
	for (const handler of first.handlers.get("session_shutdown") ?? []) await handler({}, {});

	const second = createHarness(bus.facade());
	const approvalTool = second.tools.find((tool) => tool.name === "approve_infra_command")!;
	const result = await approvalTool.execute(
		"approval-test",
		{
			request_id: requestId,
			command: "rm old-instance",
			reason: "rm command needs confirmation",
			summary: "test",
			flags: [],
			blastRadius: "test",
		},
		undefined,
		undefined,
		{ mode: "rpc" },
	);
	assert.match(result.content[0].text, /missing or expired/);
});

test("scoped bypasses apply across bash and exec_command paths within the stored cwd", async () => {
	const cwd = realpathSync(mkdtempSync(join(tmpdir(), "infra-guard-bash-")));
	try {
		const executable = join(cwd, "kubectl");
		writeFileSync(executable, '#!/bin/sh\nprintf "%s\\n" "fake-kubectl" "$PWD" "$@"\n', { mode: 0o700 });
		const kubeconfig = join(cwd, "unused-kubeconfig");
		const events = createTestEventBus().facade();
		const { handlers, pi, tools } = createHarness(events);
		const toolCall = handlers.get("tool_call")![0]!;
		const statuses: Array<string | undefined> = [];
		const context = {
			cwd,
			mode: "tui",
			ui: { setStatus(_key: string, text: string | undefined) { statuses.push(text); } },
		};
		const bypassStore = (pi.events as Record<PropertyKey, unknown>)[BYPASS_STORE_KEY] as GuardBypassStore;

		const command = `${JSON.stringify(executable)} --kubeconfig ${JSON.stringify(kubeconfig)} delete pod foo`;
		const blocked = await toolCall({ toolName: "exec_command", input: { cmd: command } }, context) as {
			block: boolean;
			reason: string;
		};
		assert.equal(blocked.block, true);
		assert.match(blocked.reason, /Approval request:/);

		bypassStore.addRule("kubectl", cwd, { kind: "kubectl-kubeconfig", path: kubeconfig }, 10 * 60 * 1000);
		assert.equal(await toolCall({ toolName: "exec_command", input: { cmd: command } }, context), undefined);

		const bash = tools.find((tool) => tool.name === "bash")!;
		const result = await bash.execute("bypass-bash", { command }, undefined, undefined, context);
		assert.equal(result.content[0].text.trim(), ["fake-kubectl", cwd, "--kubeconfig", kubeconfig, "delete", "pod", "foo"].join("\n"));

		const otherDirectory = await toolCall(
			{ toolName: "exec_command", input: { cmd: command } },
			{ ...context, cwd: "/other" },
		) as { block: boolean };
		assert.equal(otherDirectory.block, true);
		assert.ok(statuses.some((status) => status?.includes("kubectl")));
	} finally {
		rmSync(cwd, { recursive: true, force: true });
	}
});

test("bash executes in the authorized cwd when the session directory changes", async () => {
	const cwd = realpathSync(mkdtempSync(join(tmpdir(), "infra-guard-cwd-")));
	try {
		const { tools } = createHarness(createTestEventBus().facade());
		const bash = tools.find((tool) => tool.name === "bash")!;
		for (const directory of [cwd, realpathSync(process.cwd()), cwd]) {
			const result = await bash.execute("cwd-test", { command: "pwd -P" }, undefined, undefined, { cwd: directory, mode: "tui" });
			assert.equal(result.content[0].text.trim(), directory);
		}
	} finally {
		rmSync(cwd, { recursive: true, force: true });
	}
});

test("direct and nested tool paths reject compound interactive sessions even while paused", async () => {
	const bus = createTestEventBus();
	const broker = createPreflightBroker(bus.facade());
	const { handlers, pi } = createHarness(bus.facade());
	const preflight = await waitForPreflight(broker);
	const toolCall = handlers.get("tool_call")![0]!;
	const bypasses = (pi.events as Record<PropertyKey, unknown>)[BYPASS_STORE_KEY] as GuardBypassStore;
	bypasses.pause(10 * 60 * 1000);
	for (const cmd of ["true; bash", "echo ready && exec /bin/sh", "(python3)"]) {
		const direct = await toolCall({ toolName: "exec_command", input: { cmd, tty: true } }, { cwd: "/tmp", mode: "tui" });
		const nested = await preflight({ ...nestedCall(cmd), input: { cmd, tty: true } });
		for (const result of [direct, nested]) {
			assert.ok(result && typeof result === "object" && "block" in result && "reason" in result, cmd);
			assert.equal(result.block, true, cmd);
			assert.equal(typeof result.reason, "string", cmd);
			assert.match(result.reason as string, /interactive shell and interpreter sessions/, cmd);
			assert.doesNotMatch(result.reason as string, /Approval request:/, cmd);
		}
	}
	broker.shutdown();
});

test("bypass state does not leak across extension instances", async () => {
	const bus = createTestEventBus();
	const first = createHarness(bus.facade());
	const firstStore = (first.pi.events as Record<PropertyKey, unknown>)[BYPASS_STORE_KEY] as {
		pause(durationMs: number): void;
		isPaused(): boolean;
	};
	firstStore.pause(10 * 60 * 1000);
	assert.equal(firstStore.isPaused(), true);
	for (const handler of first.handlers.get("session_shutdown") ?? []) await handler({}, {});

	const second = createHarness(bus.facade());
	const secondStore = (second.pi.events as Record<PropertyKey, unknown>)[BYPASS_STORE_KEY] as {
		isPaused(): boolean;
	};
	assert.equal(secondStore.isPaused(), false);
	const toolCall = second.handlers.get("tool_call")![0]!;
	const blocked = await toolCall(
		{ toolName: "exec_command", input: { cmd: "rm after-shutdown" } },
		{ cwd: "/tmp", mode: "tui", ui: {} },
	) as { block: boolean };
	assert.equal(blocked.block, true);
	for (const handler of second.handlers.get("session_shutdown") ?? []) await handler({}, {});
});

test("extension reloads guard toggles and command rules for each command", async () => {
	const directory = mkdtempSync(join(tmpdir(), "infra-command-guard-extension-"));
	const configPath = join(directory, "infra-command-guard.json");
	const previousAgentDir = process.env.PI_CODING_AGENT_DIR;
	process.env.PI_CODING_AGENT_DIR = directory;
	try {
		const events = createTestEventBus().facade();
		const { handlers, pi, tools } = createHarness(events);
		const toolCall = handlers.get("tool_call")![0]!;
		const warnings: string[] = [];
		const context = {
			cwd: directory,
			mode: "tui",
			ui: { notify(message: string) { warnings.push(message); } },
		};
		writeFileSync(join(directory, "README.md"), "kubectl test fixture\n");

		writeFileSync(configPath, JSON.stringify({ guards: { rm: false } }));
		assert.equal(await toolCall({ toolName: "exec_command", input: { cmd: "rm disabled" } }, context), undefined);
		writeFileSync(configPath, JSON.stringify({
			guards: { rm: false },
			commands: { rm: { requireApproval: ["disabled"] } },
		}));
		assert.equal(await toolCall({ toolName: "exec_command", input: { cmd: "rm disabled" } }, context), undefined);

		writeFileSync(configPath, JSON.stringify({ guards: { rm: true } }));
		const enabled = await toolCall({ toolName: "exec_command", input: { cmd: "rm enabled" } }, context) as { block: boolean; reason: string };
		assert.equal(enabled.block, true);
		assert.match(enabled.reason, /Approval request:/);
		const requestId = enabled.reason.match(/Approval request: ([0-9a-f-]+)/)?.[1];
		assert.ok(requestId);
		const store = (pi.events as Record<PropertyKey, unknown>)[APPROVAL_STORE_KEY] as { approve: (...args: string[]) => { ok: boolean } };
		assert.equal(store.approve(requestId, "rm enabled", "rm command needs confirmation").ok, true);

		const searchCommand = "grep kubectl README.md";
		writeFileSync(configPath, JSON.stringify({}));
		const conservativeSearch = await toolCall(
			{ toolName: "exec_command", input: { cmd: searchCommand } },
			context,
		) as { block: boolean; reason: string };
		assert.equal(conservativeSearch.block, true);
		assert.match(conservativeSearch.reason, /invokes guarded tooling/);

		writeFileSync(configPath, JSON.stringify({ guardUnclassifiedCommands: false }));
		assert.equal(await toolCall({ toolName: "exec_command", input: { cmd: searchCommand } }, context), undefined);
		const incompatibleCodeMode = await toolCall({ toolName: "exec", input: { code: "dynamic" } }, context) as {
			block: boolean;
			reason: string;
		};
		assert.equal(incompatibleCodeMode.block, true);
		assert.match(incompatibleCodeMode.reason, /cannot safely intercept Code Mode/);
		const stillRisky = await toolCall({ toolName: "exec_command", input: { cmd: "rm enabled" } }, context) as { block: boolean };
		assert.equal(stillRisky.block, true, "changing the mode invalidates the unused approval and keeps known risk guarded");
		const bash = tools.find((tool) => tool.name === "bash")!;
		await bash.execute("relaxed-bash", { command: searchCommand }, undefined, undefined, context);

		writeFileSync(configPath, JSON.stringify({ guards: ALL_GUARDS_DISABLED }));
		assert.equal(await toolCall({ toolName: "exec", input: { code: "dynamic" } }, context), undefined);

		writeFileSync(configPath, JSON.stringify({ commands: { rm: { allow: ["custom-target"] } } }));
		assert.equal(await toolCall({ toolName: "exec_command", input: { cmd: "rm custom-target" } }, context), undefined);
		writeFileSync(configPath, JSON.stringify({ commands: { rm: { requireApproval: ["custom-target"] } } }));
		const customRequired = await toolCall(
			{ toolName: "exec_command", input: { cmd: "rm custom-target" } },
			context,
		) as { block: boolean; reason: string };
		assert.equal(customRequired.block, true);
		assert.match(customRequired.reason, /Custom command rule requires approval/);

		writeFileSync(configPath, JSON.stringify({ guardUnclassifiedCommands: "off" }));
		const invalid = await toolCall({ toolName: "exec_command", input: { cmd: "rm enabled" } }, context) as { block: boolean };
		assert.equal(invalid.block, true);
		assert.equal(warnings.length, 1);
		assert.match(warnings[0]!, /All command guards remain enabled/);
		const invalidSearch = await toolCall(
			{ toolName: "exec_command", input: { cmd: searchCommand } },
			context,
		) as { block: boolean };
		assert.equal(invalidSearch.block, true, "invalid mode falls back to conservative classification");
		await toolCall({ toolName: "exec_command", input: { cmd: "rm invalid-config-again" } }, context);
		assert.equal(warnings.length, 1);
	} finally {
		if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
		else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
		rmSync(directory, { recursive: true, force: true });
	}
});

test("Code Mode reloads guard toggles and command rules without losing preflight interception", async () => {
	const directory = mkdtempSync(join(tmpdir(), "infra-command-guard-code-mode-config-"));
	const configPath = join(directory, "infra-command-guard.json");
	const previousAgentDir = process.env.PI_CODING_AGENT_DIR;
	process.env.PI_CODING_AGENT_DIR = directory;
	try {
		const bus = createTestEventBus();
		const broker = createPreflightBroker(bus.facade());
		createHarness(bus.facade());
		const preflight = await waitForPreflight(broker);

		writeFileSync(configPath, JSON.stringify({ guards: ALL_GUARDS_DISABLED }));
		assert.equal(await preflight(nestedCall("rm disabled")), undefined);

		writeFileSync(configPath, JSON.stringify({ guards: { rm: false, terraform: true } }));
		assert.equal(await preflight(nestedCall("rm disabled")), undefined);
		const terraform = await preflight(nestedCall("rm disabled && terraform apply"));
		assert.equal(terraform?.block, true);
		assert.match(terraform?.reason ?? "", /terraform apply is not on the low-risk allowlist/);

		const searchCommand = "grep kubectl README.md";
		writeFileSync(configPath, JSON.stringify({ guardUnclassifiedCommands: false }));
		assert.equal(await preflight(nestedCall(searchCommand)), undefined);
		writeFileSync(configPath, JSON.stringify({ guardUnclassifiedCommands: true }));
		const conservative = await preflight(nestedCall(searchCommand));
		assert.equal(conservative?.block, true);
		assert.match(conservative?.reason ?? "", /invokes guarded tooling/);

		writeFileSync(configPath, JSON.stringify({ commands: { rm: { allow: ["code-mode-target"] } } }));
		assert.equal(await preflight(nestedCall("rm code-mode-target")), undefined);
		writeFileSync(configPath, JSON.stringify({ commands: { rm: { requireApproval: ["code-mode-target"] } } }));
		const required = await preflight(nestedCall("rm code-mode-target"));
		assert.equal(required?.block, true);
		assert.match(required?.reason ?? "", /Custom command rule requires approval/);

		writeFileSync(configPath, JSON.stringify({ guards: { rm: "off" } }));
		const invalid = await preflight(nestedCall("rm invalid-config"));
		assert.equal(invalid?.block, true);
		assert.match(invalid?.reason ?? "", /rm command needs confirmation/);
		broker.shutdown();
	} finally {
		if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
		else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
		rmSync(directory, { recursive: true, force: true });
	}
});

test("TypeSafe review is off by default: no credentials, no requests, unchanged approvals", async () => {
	await withAgentDir("infra-command-guard-typesafe-off-", async () => {
		const transport = createTypeSafeTransport(() => jsonTypeSafeResponse(judgedTypeSafeBody("mismatched")), {});
		const harness = createHarness(createTestEventBus().facade(), { typeSafeTransport: transport });
		const notifications: string[] = [];
		const approved = await approveBlocked(harness, "rm default-off-target", "y", { notifications });
		assert.equal(approved.result.details.approved, true);
		assert.doesNotMatch(approved.rendered, /TypeSafe/);
		assert.equal(transport.calls.length, 0);
		assert.equal(notifications.length, 0);
		const approvals = (harness.pi.events as Record<PropertyKey, unknown>)[APPROVAL_STORE_KEY] as ApprovalStore;
		assert.equal(approvals.consume(executionIdentity("exec-command", { cmd: "rm default-off-target" }, "/tmp")!), true);
		assert.equal(transport.calls.length, 0);
		const store = (harness.pi.events as Record<PropertyKey, unknown>)[TYPESAFE_STORE_KEY] as TypeSafeReviewStore;
		assert.equal(store.size(), 0);
		await harness.commands.get("infra-guard-typesafe")!.handler("status", {
			hasUI: false,
			mode: "rpc",
			ui: { notify(message: string) { notifications.push(message); } },
		});
		assert.match(notifications.at(-1) ?? "", /TypeSafe review: disabled/);
	});
});

test("TypeSafe review consults only known-risk blocks and renders every verdict as advisory", async () => {
	await withAgentDir("infra-command-guard-typesafe-gate-", async (_directory, configPath) => {
		writeFileSync(configPath, JSON.stringify({ integrations: { typesafe: { enabled: true } } }));
		let nextVerdict: ReviewVerdict = "supported";
		const transport = createTypeSafeTransport(() => jsonTypeSafeResponse(judgedTypeSafeBody(nextVerdict, 0.7)));
		const harness = createHarness(createTestEventBus().facade(), { typeSafeTransport: transport });
		const toolCall = harness.handlers.get("tool_call")![0]!;
		const context = { cwd: "/tmp", mode: "tui", ui: { notify() {}, setStatus() {} } };

		const expectations: Record<ReviewVerdict, RegExp> = {
			supported: /Verdict: Supported — the reason identifies an executable operation or effect/,
			partially_supported: /Verdict: Partially supported/,
			mismatched: /Verdict: Mismatched — the reason may not describe this command; the deterministic block still stands/,
			insufficient_evidence: /Verdict: Insufficient evidence/,
		};
		let expectedCalls = 0;
		for (const verdict of REVIEW_VERDICTS) {
			nextVerdict = verdict;
			const cmd = `rm known-risk-${verdict}`;
			const approved = await approveBlocked(harness, cmd, "y");
			expectedCalls += 1;
			assert.equal(transport.calls.length, expectedCalls, cmd);
			const call = transport.calls.at(-1)!;
			assert.equal(call.url, "https://api.typesafe.ai/v1/systemone");
			assert.equal(call.init.method, "POST");
			assert.equal((call.init.headers as Record<string, string>).Authorization, "Bearer test-key");
			assert.equal(call.body.model, TYPESAFE_MODEL);
			assert.equal(call.body.state.command, cmd);
			assert.equal(call.body.state.guard_reason, approved.reason);
			assert.deepEqual(Object.keys(call.body.questions.reason_match.criteria), [...REVIEW_VERDICTS]);
			assert.match(approved.rendered, /Guard reason .* TypeSafe review — experimental, advisory only/);
			assert.match(approved.rendered, expectations[verdict]);
			assert.match(approved.rendered, /Distribution: supported 0\.\d\d · partially supported 0\.\d\d · mismatched 0\.\d\d · insufficient evidence 0\.\d\d/);
			assert.match(approved.rendered, /Confidence 0\.70 measures how concentrated that distribution is, not whether the verdict is correct/);
			assert.match(approved.rendered, /does not change the block or grant approval/);
			assert.equal(approved.result.details.approved, true, "approval is still the human's decision");
			// The approved retry consumes the grant without a further request.
			assert.equal(await toolCall({ toolName: "exec_command", input: { cmd } }, context), undefined);
			assert.equal(transport.calls.length, expectedCalls);
		}

		// Re-blocking the identical command reuses the cached review.
		const reblocked = await toolCall({ toolName: "exec_command", input: { cmd: "rm known-risk-supported" } }, context) as { block: boolean };
		assert.equal(reblocked.block, true);
		assert.equal(transport.calls.length, expectedCalls);

		// Allowed commands never reach TypeSafe.
		assert.equal(await toolCall({ toolName: "exec_command", input: { cmd: "git status" } }, context), undefined);
		assert.equal(transport.calls.length, expectedCalls);

		// Unclassified blocks are not reviewed and say so.
		const unclassified = await approveBlocked(harness, "$TOOL unclassified-target", "y");
		assert.match(unclassified.reason, /shell variable/);
		assert.equal(transport.calls.length, expectedCalls);
		assert.match(unclassified.rendered, /Not consulted: TypeSafe reviews only blocks based on a positively recognized risk/);
		assert.equal(unclassified.result.details.approved, true);

		// Custom requireApproval rules are not reviewed either.
		writeFileSync(configPath, JSON.stringify({
			integrations: { typesafe: { enabled: true } },
			commands: { git: { requireApproval: ["status"] } },
		}));
		const customRule = await approveBlocked(harness, "git status", "y");
		assert.match(customRule.reason, /Custom command rule requires approval/);
		assert.equal(transport.calls.length, expectedCalls);
		assert.match(customRule.rendered, /Not consulted/);

		// Non-TUI blocks have no approval overlay and make no request.
		const rpc = await toolCall({ toolName: "exec_command", input: { cmd: "rm rpc-target" } }, { cwd: "/tmp", mode: "rpc" }) as { block: boolean };
		assert.equal(rpc.block, true);
		assert.equal(transport.calls.length, expectedCalls);

		// A mismatched verdict never approves anything: cancel still cancels.
		nextVerdict = "mismatched";
		const cancelled = await approveBlocked(harness, "rm cancelled-target", "n");
		assert.equal(transport.calls.length, expectedCalls + 1);
		assert.match(cancelled.rendered, /Verdict: Mismatched/);
		assert.equal(cancelled.result.details.approved, false);
		const approvals = (harness.pi.events as Record<PropertyKey, unknown>)[APPROVAL_STORE_KEY] as ApprovalStore;
		assert.equal(approvals.consume(executionIdentity("exec-command", { cmd: "rm cancelled-target" }, "/tmp")!), false);
		const stillBlocked = await toolCall({ toolName: "exec_command", input: { cmd: "rm cancelled-target" } }, context) as { block: boolean };
		assert.equal(stillBlocked.block, true);
	});
});

test("TypeSafe review covers bash and Code Mode block paths with a single request each", async () => {
	await withAgentDir("infra-command-guard-typesafe-paths-", async (_directory, configPath) => {
		writeFileSync(configPath, JSON.stringify({ integrations: { typesafe: { enabled: true } } }));
		const transport = createTypeSafeTransport(() => jsonTypeSafeResponse(judgedTypeSafeBody("supported")));
		const bus = createTestEventBus();
		const broker = createPreflightBroker(bus.facade());
		const harness = createHarness(bus.facade(), { typeSafeTransport: transport });
		const preflight = await waitForPreflight(broker);
		const nested = await preflight(nestedCall("rm code-mode-target"));
		assert.equal(nested?.block, true);
		assert.equal(transport.calls.length, 1);
		assert.equal(transport.calls[0]!.body.state.command, "rm code-mode-target");

		const bash = harness.tools.find((tool) => tool.name === "bash")!;
		await assert.rejects(
			bash.execute("bash-block", { command: "rm bash-target" }, undefined, undefined, { cwd: "/tmp", mode: "tui", ui: { setStatus() {}, notify() {} } }),
			/Approval request:/,
		);
		assert.equal(transport.calls.length, 2);
		assert.equal(transport.calls[1]!.body.state.command, "rm bash-target");
		await assert.rejects(
			bash.execute("bash-block", { command: "rm bash-target" }, undefined, undefined, { cwd: "/tmp", mode: "tui", ui: { setStatus() {}, notify() {} } }),
			/Approval request:/,
		);
		assert.equal(transport.calls.length, 2, "re-blocking the same bash command reuses the review");
		broker.shutdown();
	});
});

test("TypeSafe failures stay visible in the overlay and leave the approval flow intact", async () => {
	await withAgentDir("infra-command-guard-typesafe-failures-", async (_directory, configPath) => {
		writeFileSync(configPath, JSON.stringify({ integrations: { typesafe: { enabled: true } } }));

		const unauthorized = createTypeSafeTransport(() => jsonTypeSafeResponse({ detail: "Invalid API key" }, 401));
		const unauthorizedHarness = createHarness(createTestEventBus().facade(), { typeSafeTransport: unauthorized });
		const notifications: string[] = [];
		const failed = await approveBlocked(unauthorizedHarness, "rm unauthorized-target", "y", { notifications });
		assert.match(failed.rendered, /Not available: TypeSafe request failed \(HTTP 401 \(check TYPESAFE_API_KEY\): Invalid API key\)/);
		assert.equal(failed.result.details.approved, true);
		assert.equal(unauthorized.calls.length, 1);

		const malformed = createTypeSafeTransport(() => jsonTypeSafeResponse({ answers: { reason_match: { type: "choice", choice: "safe", confidence: 1, probabilities: {} } } }));
		const malformedHarness = createHarness(createTestEventBus().facade(), { typeSafeTransport: malformed });
		const shape = await approveBlocked(malformedHarness, "rm malformed-target", "y");
		assert.match(shape.rendered, /Not available: TypeSafe request failed \(response choice is not a known verdict: safe\)/);
		assert.equal(shape.result.details.approved, true);

		const network = createTypeSafeTransport(() => Promise.reject(new Error("ECONNRESET")));
		const networkHarness = createHarness(createTestEventBus().facade(), { typeSafeTransport: network });
		const offline = await approveBlocked(networkHarness, "rm offline-target", "n");
		assert.match(offline.rendered, /Not available: TypeSafe request failed \(ECONNRESET\)/);
		assert.equal(offline.result.details.approved, false);

		const missing = createTypeSafeTransport(() => jsonTypeSafeResponse(judgedTypeSafeBody("supported")), {});
		const missingHarness = createHarness(createTestEventBus().facade(), { typeSafeTransport: missing });
		const missingNotifications: string[] = [];
		const noKey = await approveBlocked(missingHarness, "rm missing-key-target", "y", { notifications: missingNotifications });
		assert.equal(missing.calls.length, 0, "no request is attempted without credentials");
		assert.match(noKey.rendered, /Not available: TYPESAFE_API_KEY is not set in Pi's environment/);
		assert.equal(noKey.result.details.approved, true);
		assert.equal(missingNotifications.filter((message) => /TYPESAFE_API_KEY is not set/.test(message)).length, 1);
		await approveBlocked(missingHarness, "rm missing-key-again", "y", { notifications: missingNotifications });
		assert.equal(missingNotifications.filter((message) => /TYPESAFE_API_KEY is not set/.test(message)).length, 1, "the credential warning is not repeated");
	});
});

test("/infra-guard-typesafe enables, pauses, resumes, and disables the review independently of the guard", async () => {
	await withAgentDir("infra-command-guard-typesafe-command-", async (_directory, configPath) => {
		writeFileSync(configPath, JSON.stringify({ guards: { az: false }, notifications: { enabled: false } }));
		const transport = createTypeSafeTransport(() => jsonTypeSafeResponse(judgedTypeSafeBody("supported")));
		const harness = createHarness(createTestEventBus().facade(), { typeSafeTransport: transport });
		const command = harness.commands.get("infra-guard-typesafe")!;
		const toolCall = harness.handlers.get("tool_call")![0]!;
		const store = (harness.pi.events as Record<PropertyKey, unknown>)[TYPESAFE_STORE_KEY] as TypeSafeReviewStore;
		const bypasses = (harness.pi.events as Record<PropertyKey, unknown>)[BYPASS_STORE_KEY] as GuardBypassStore;
		const notifications: string[] = [];
		const statuses: Array<string | undefined> = [];
		const context = {
			cwd: "/tmp",
			mode: "tui",
			ui: {
				notify(message: string) { notifications.push(message); },
				setStatus(_key: string, value: string | undefined) { statuses.push(value); },
			},
		};
		const run = (args: string, selections: string[] = [], inspect?: (title: string, options: string[]) => void) => {
			let index = 0;
			return command.handler(args, {
				hasUI: true,
				mode: "tui",
				ui: {
					...context.ui,
					async select(title: string, options: string[]) {
						inspect?.(title, options);
						return selections[index++];
					},
				},
			});
		};
		const readConfig = () => JSON.parse(readFileSync(configPath, "utf8"));

		await run("status");
		assert.match(notifications.at(-1)!, /TypeSafe review: disabled/);
		await run("pause 1h");
		assert.match(notifications.at(-1)!, /already disabled in configuration/);
		await run("", [], (_title, options) => assert.deepEqual(options, ["Enable TypeSafe review (saves to configuration)"]));

		await run("enable");
		assert.deepEqual(readConfig(), {
			guards: { az: false },
			notifications: { enabled: false },
			integrations: { typesafe: { enabled: true } },
		});
		assert.match(notifications.at(-1)!, /TypeSafe review enabled and saved/);
		assert.match(notifications.at(-1)!, /approval is unchanged/);
		await run("status");
		assert.match(notifications.at(-1)!, /TypeSafe review: enabled \(advisory only, 8000 ms timeout\)/);

		const enabledBlock = await toolCall({ toolName: "exec_command", input: { cmd: "rm enabled-target" } }, context) as { block: boolean };
		assert.equal(enabledBlock.block, true);
		assert.equal(transport.calls.length, 1);

		await run("pause 1 hour");
		assert.equal(store.pause.isPaused(), true);
		assert.equal(bypasses.isPaused(), false, "pausing the review never pauses the guard");
		assert.match(notifications.at(-1)!, /TypeSafe review paused for 1 hour in this session; the guard itself is unchanged/);
		assert.match(statuses.at(-1) ?? "", /TypeSafe review paused for 1 hour/);
		const pausedBlock = await toolCall({ toolName: "exec_command", input: { cmd: "rm paused-target" } }, context) as { block: boolean };
		assert.equal(pausedBlock.block, true, "the guard still blocks while the review is paused");
		assert.equal(transport.calls.length, 1, "no request while paused");
		const pausedOverlay = await approveBlocked(harness, "rm paused-overlay-target", "y");
		assert.doesNotMatch(pausedOverlay.rendered, /TypeSafe/);
		assert.equal(transport.calls.length, 1);
		await run("status");
		assert.match(notifications.at(-1)!, /TypeSafe review: enabled, paused for 1 hour/);
		assert.equal(readConfig().integrations.typesafe.enabled, true, "a pause is never persisted");

		await run("resume");
		assert.equal(store.pause.isPaused(), false);
		assert.equal(statuses.at(-1), undefined);
		await toolCall({ toolName: "exec_command", input: { cmd: "rm resumed-target" } }, context);
		assert.equal(transport.calls.length, 2);

		await run("pause nonsense");
		assert.match(notifications.at(-1)!, /Unknown pause duration "nonsense"/);
		assert.equal(store.pause.isPaused(), false);
		await run("frobnicate");
		assert.match(notifications.at(-1)!, /^Usage: \/infra-guard-typesafe/);

		await run("", ["Pause TypeSafe review…", "10 minutes"], (_title, options) => {
			if (options.includes("Pause TypeSafe review…")) {
				assert.deepEqual(options, ["Pause TypeSafe review…", "Disable TypeSafe review (saves to configuration)"]);
			}
		});
		assert.equal(store.pause.isPaused(), true);
		await run("", ["Resume TypeSafe review now"], (title, options) => {
			assert.match(title, /paused for 10 minutes/);
			assert.deepEqual(options, ["Resume TypeSafe review now", "Disable TypeSafe review (saves to configuration)"]);
		});
		assert.equal(store.pause.isPaused(), false);

		await run("", ["Disable TypeSafe review (saves to configuration)"]);
		assert.equal(readConfig().integrations.typesafe.enabled, false);
		assert.deepEqual(readConfig().guards, { az: false });
		assert.match(notifications.at(-1)!, /TypeSafe review disabled and saved/);
		assert.equal(store.size(), 0);
		await toolCall({ toolName: "exec_command", input: { cmd: "rm disabled-target" } }, context);
		assert.equal(transport.calls.length, 2, "no request after disabling");

		writeFileSync(configPath, "{ broken");
		await run("enable");
		assert.match(notifications.at(-1)!, /cannot change TypeSafe settings while .* is invalid/);
		assert.equal(readFileSync(configPath, "utf8"), "{ broken");
		await run("", [], () => assert.fail("no menu for an invalid configuration"));
		assert.match(notifications.at(-1)!, /configuration invalid/);
	});
});

test("pausing or disabling TypeSafe mid-flight discards the pending review", async () => {
	await withAgentDir("infra-command-guard-typesafe-inflight-", async (_directory, configPath) => {
		writeFileSync(configPath, JSON.stringify({ integrations: { typesafe: { enabled: true } } }));
		let release: ((response: Response) => void) | undefined;
		let aborted = 0;
		const transport = createTypeSafeTransport((_call, signal) => new Promise<Response>((resolve, reject) => {
			release = resolve;
			signal?.addEventListener("abort", () => {
				aborted += 1;
				reject(new Error("aborted"));
			});
		}));
		const harness = createHarness(createTestEventBus().facade(), { typeSafeTransport: transport });
		const toolCall = harness.handlers.get("tool_call")![0]!;
		const store = (harness.pi.events as Record<PropertyKey, unknown>)[TYPESAFE_STORE_KEY] as TypeSafeReviewStore;
		const context = { cwd: "/tmp", mode: "tui", ui: { notify() {}, setStatus() {} } };
		const blocked = await toolCall({ toolName: "exec_command", input: { cmd: "rm inflight-target" } }, context) as { block: boolean; reason: string };
		assert.equal(blocked.block, true);
		assert.equal(transport.calls.length, 1);
		assert.ok(release);

		await harness.commands.get("infra-guard-typesafe")!.handler("pause 10m", { hasUI: true, mode: "tui", ui: { notify() {}, setStatus() {}, async select() { return undefined; } } });
		assert.equal(aborted, 1, "pausing aborts the in-flight request");
		assert.equal(store.size(), 0);

		const requestId = blocked.reason.match(/Approval request: ([^\n]+)/)?.[1]!;
		const reason = blocked.reason.match(/^BLOCKED — ([^\n]+)/)?.[1]!;
		const approve = harness.tools.find((tool) => tool.name === "approve_infra_command")!;
		const theme = { fg: (_color: string, text: string) => text, bold: (text: string) => text, bg: (_color: string, text: string) => text };
		const renderApproval = async (command: string, pendingId: string, pendingReason: string) => {
			let rendered = "";
			const result = await approve.execute(
				"approve-inflight",
				{ request_id: pendingId, command, reason: pendingReason, summary: "s", flags: [], blastRadius: "b" },
				new AbortController().signal,
				undefined,
				{
					...context,
					ui: {
						...context.ui,
						async custom(factory: (...args: any[]) => { render(width: number): string[]; handleInput(data: string): void }) {
							let choice = "cancel";
							const overlay = factory({ requestRender() {}, terminal: { rows: 80 } }, theme, { matches: () => false }, (selected: string) => { choice = selected; });
							rendered = overlay.render(160).join(" ").replace(/\s+/g, " ");
							overlay.handleInput("n");
							return choice;
						},
						async select() { return undefined; },
					},
				},
			);
			return { rendered, result };
		};
		const paused = await renderApproval("rm inflight-target", requestId, reason);
		assert.doesNotMatch(paused.rendered, /TypeSafe/, "a paused review shows nothing, not a stale result");
		assert.equal(paused.result.details.approved, false);

		// A command blocked while paused has no review; after resuming, the overlay says so
		// instead of starting a request from the approval tool.
		const blockedWhilePaused = await toolCall({ toolName: "exec_command", input: { cmd: "rm blocked-while-paused" } }, context) as { reason: string };
		assert.equal(transport.calls.length, 1);
		store.pause.resume();
		const resumed = await renderApproval(
			"rm blocked-while-paused",
			blockedWhilePaused.reason.match(/Approval request: ([^\n]+)/)?.[1]!,
			blockedWhilePaused.reason.match(/^BLOCKED — ([^\n]+)/)?.[1]!,
		);
		assert.match(resumed.rendered, /Not consulted: TypeSafe review was disabled, paused, or unavailable when this command was blocked/);
		assert.equal(transport.calls.length, 1, "the approval tool never starts a request on its own");

		for (const handler of harness.handlers.get("session_shutdown") ?? []) await handler({}, {});
		assert.equal((harness.pi.events as Record<PropertyKey, unknown>)[TYPESAFE_STORE_KEY], undefined);
	});
});

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
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

function createHarness(events: EventFacade) {
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
	createExtension(pi as never);
	return { commands, handlers, pi, tools };
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

		bypasses.addRule("kubectl", "/repo", { kind: "command-prefix", tokens: ["delete", "pod", "api"] }, 10 * 60 * 1000);
		const removeOption = `Remove bypass: ${bypasses.describeRule(bypasses.listRules()[0]!)}`;
		await runMenu([removeOption], (_title, options) => {
			assert.deepEqual(options, ["Pause guard…", removeOption]);
		});
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
	const events = createTestEventBus().facade();
	const { handlers, pi, tools } = createHarness(events);
	const toolCall = handlers.get("tool_call")![0]!;
	const statuses: Array<string | undefined> = [];
	const context = {
		cwd: "/repo",
		mode: "tui",
		ui: { setStatus(_key: string, text: string | undefined) { statuses.push(text); } },
	};
	const bypassStore = (pi.events as Record<PropertyKey, unknown>)[BYPASS_STORE_KEY] as {
		addRule(
			executable: "kubectl",
			cwd: string,
			scope: { kind: "kubectl-kubeconfig"; path: string },
			durationMs: number,
		): void;
	};

	const command = "kubectl --kubeconfig /tmp/kc delete pod foo";
	const blocked = await toolCall({ toolName: "exec_command", input: { cmd: command } }, context) as {
		block: boolean;
		reason: string;
	};
	assert.equal(blocked.block, true);
	assert.match(blocked.reason, /Approval request:/);

	bypassStore.addRule("kubectl", "/repo", { kind: "kubectl-kubeconfig", path: "/tmp/kc" }, 10 * 60 * 1000);
	assert.equal(await toolCall({ toolName: "exec_command", input: { cmd: command } }, context), undefined);

	const bash = tools.find((tool) => tool.name === "bash")!;
	await assert.rejects(
		bash.execute("bypass-bash", { command: "kubectl --kubeconfig /tmp/kc apply -f x.yaml" }, undefined, undefined, context),
		/error: stat \/tmp\/kc/,
		"bypassed bash command reaches kubectl itself",
	);

	const otherDirectory = await toolCall(
		{ toolName: "exec_command", input: { cmd: command } },
		{ ...context, cwd: "/other" },
	) as { block: boolean };
	assert.equal(otherDirectory.block, true);
	assert.ok(statuses.some((status) => status?.includes("kubectl")));
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
			cwd: "/tmp",
			mode: "tui",
			ui: { notify(message: string) { warnings.push(message); } },
		};

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

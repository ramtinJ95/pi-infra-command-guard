import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { APPROVAL_STORE_KEY } from "./approvals.ts";
import {
	CODE_MODE_GUARD_BRIDGE_KEY,
	CODE_MODE_RUNTIME_KEY,
} from "./code-mode.ts";
import createExtension from "./index.ts";
import { test } from "./test-harness.ts";

const ALL_GUARDS_DISABLED = {
	argocd: false,
	aws: false,
	az: false,
	gcloud: false,
	helm: false,
	kubectl: false,
	rm: false,
	terraform: false,
};

test("outer Code Mode calls fail closed when the private runtime is absent", async () => {
	const handlers = new Map<string, Array<(event: any, context: any) => unknown>>();
	const pi = {
		events: {},
		registerCommand() {},
		registerTool() {},
		on(name: string, handler: (event: any, context: any) => unknown) {
			handlers.set(name, [...(handlers.get(name) ?? []), handler]);
		},
	};
	createExtension(pi as never);
	const toolCall = handlers.get("tool_call")![0]!;
	for (const toolName of ["exec", "wait", "functions.exec", "functions.wait"]) {
		const decision = await toolCall({ toolName, input: {} }, { cwd: "/tmp", mode: "tui" });
		assert.deepEqual(decision, {
			block: true,
			reason: "BLOCKED — infra-command-guard cannot safely intercept Code Mode: Code Mode runtime was not found. Reload Pi or disable Code Mode before running commands.",
		});
	}
});

test("extension outer exec hook installs the nested guard before Code Mode collects tools", async () => {
	let invokeCount = 0;
	const provider = {
		getTools() {
			return [
				{
					name: "exec_command",
					async invoke(_input?: unknown, _context?: unknown, _signal?: AbortSignal) {
						invokeCount += 1;
					},
				},
			];
		},
	};
	const events: Record<PropertyKey, unknown> = {
		[CODE_MODE_RUNTIME_KEY]: { runtime: { providers: new Map([[{}, provider]]) } },
	};
	const handlers = new Map<string, Array<(event: any, context: any) => unknown>>();
	const pi = {
		events,
		registerCommand() {},
		registerTool() {},
		on(name: string, handler: (event: any, context: any) => unknown) {
			handlers.set(name, [...(handlers.get(name) ?? []), handler]);
		},
	};
	createExtension(pi as never);
	const context = { cwd: "/tmp", mode: "tui" };
	for (const handler of handlers.get("before_agent_start") ?? []) {
		assert.equal(await handler({}, context), undefined);
	}
	const preparedNested = provider.getTools()[0]!;
	await assert.rejects(
		preparedNested.invoke(
			{ cmd: "rm prepared-target" },
			{ cwd: "/tmp", extensionContext: context },
		),
		/Approval request:/,
	);
	assert.equal(invokeCount, 0);
	for (const handler of handlers.get("tool_call") ?? []) {
		assert.equal(await handler({ toolName: "exec", input: { code: "dynamic" } }, context), undefined);
	}
	const nested = provider.getTools()[0]!;
	await assert.rejects(
		nested.invoke(
			{ cmd: "rm guarded-target" },
			{ cwd: "/tmp", extensionContext: context },
		),
		/Approval request:/,
	);
	assert.equal(invokeCount, 0);
});

test("Code Mode wrapper switches bridges safely across guard reloads", async () => {
	let invokeCount = 0;
	const provider = {
		getTools() {
			return [
				{
					name: "exec_command",
					async invoke(_input?: unknown, _context?: unknown, _signal?: AbortSignal) {
						invokeCount += 1;
					},
				},
			];
		},
	};
	const events: Record<PropertyKey, unknown> = {
		[CODE_MODE_RUNTIME_KEY]: { runtime: { providers: new Map([[{}, provider]]) } },
	};
	const createPi = () => {
		const handlers = new Map<string, Array<(event: any, context: any) => unknown>>();
		return {
			pi: {
				events,
				registerCommand() {},
				registerTool() {},
				on(name: string, handler: (event: any, context: any) => unknown) {
					handlers.set(name, [...(handlers.get(name) ?? []), handler]);
				},
			},
			handlers,
		};
	};
	const context = { cwd: "/tmp", mode: "tui" };
	const first = createPi();
	createExtension(first.pi as never);
	for (const handler of first.handlers.get("before_agent_start") ?? []) await handler({}, context);
	const wrappedBeforeReload = provider.getTools()[0]!;
	await assert.rejects(
		wrappedBeforeReload.invoke({ cmd: "rm first" }, { cwd: "/tmp", extensionContext: context }),
		/Approval request:/,
	);
	for (const handler of first.handlers.get("session_shutdown") ?? []) await handler({}, context);
	await assert.rejects(
		wrappedBeforeReload.invoke({ cmd: "printf safe" }, { cwd: "/tmp", extensionContext: context }),
		/bridge is unavailable/,
	);

	const second = createPi();
	createExtension(second.pi as never);
	for (const handler of second.handlers.get("before_agent_start") ?? []) await handler({}, context);
	await assert.rejects(
		wrappedBeforeReload.invoke({ cmd: "rm second" }, { cwd: "/tmp", extensionContext: context }),
		/Approval request:/,
	);
	assert.equal(invokeCount, 0);
});

test("stale approval tool closures follow the current reload store", async () => {
	const events: Record<PropertyKey, unknown> = {};
	const createPi = () => {
		const tools: any[] = [];
		return {
			pi: {
				events,
				registerCommand() {},
				registerTool(tool: any) {
					tools.push(tool);
				},
				on() {},
			},
			tools,
		};
	};
	const first = createPi();
	createExtension(first.pi as never);
	const firstStore = events[APPROVAL_STORE_KEY];
	const staleApprovalTool = first.tools.find((tool) => tool.name === "approve_infra_command")!;
	assert.ok(staleApprovalTool.parameters.required.includes("request_id"));

	const second = createPi();
	createExtension(second.pi as never);
	assert.notEqual(events[APPROVAL_STORE_KEY], firstStore);
	const bridge = events[CODE_MODE_GUARD_BRIDGE_KEY] as (input: unknown, context: unknown) => void;
	let blocked = "";
	try {
		bridge({ cmd: "rm stale-reload-test" }, { cwd: "/tmp", extensionContext: { mode: "tui" } });
	} catch (error) {
		blocked = error instanceof Error ? error.message : String(error);
	}
	const requestId = blocked.match(/Approval request: ([0-9a-f-]+)/)?.[1];
	assert.ok(requestId);
	const result = await staleApprovalTool.execute(
		"approval-test",
		{
			request_id: requestId,
			command: "rm stale-reload-test",
			reason: "rm command needs confirmation",
			summary: "test",
			flags: [],
			blastRadius: "test",
		},
		undefined,
		undefined,
		{ mode: "rpc" },
	);
	assert.match(result.content[0].text, /TUI approval UI is not available/);
});

test("extension reloads guard toggles and command rules for each command", async () => {
	const directory = mkdtempSync(join(tmpdir(), "infra-command-guard-extension-"));
	const configPath = join(directory, "infra-command-guard.json");
	const previousAgentDir = process.env.PI_CODING_AGENT_DIR;
	process.env.PI_CODING_AGENT_DIR = directory;
	try {
		const handlers = new Map<string, Array<(event: any, context: any) => unknown>>();
		const pi = {
			events: {},
			registerCommand() {},
			registerTool() {},
			on(name: string, handler: (event: any, context: any) => unknown) {
				handlers.set(name, [...(handlers.get(name) ?? []), handler]);
			},
		};
		createExtension(pi as never);
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

		writeFileSync(configPath, JSON.stringify({ guards: { rm: "off" } }));
		const invalid = await toolCall({ toolName: "exec_command", input: { cmd: "rm enabled" } }, context) as { block: boolean };
		assert.equal(invalid.block, true);
		assert.equal(warnings.length, 1);
		assert.match(warnings[0]!, /All command guards remain enabled/);
		await toolCall({ toolName: "exec_command", input: { cmd: "rm invalid-config-again" } }, context);
		assert.equal(warnings.length, 1);
	} finally {
		if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
		else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
		rmSync(directory, { recursive: true, force: true });
	}
});

test("Code Mode reloads guard toggles and command rules without losing interception", async () => {
	const directory = mkdtempSync(join(tmpdir(), "infra-command-guard-code-mode-config-"));
	const configPath = join(directory, "infra-command-guard.json");
	const previousAgentDir = process.env.PI_CODING_AGENT_DIR;
	process.env.PI_CODING_AGENT_DIR = directory;
	try {
		let invokeCount = 0;
		const provider = {
			getTools() {
				return [{
					name: "exec_command",
					async invoke(_input?: unknown, _context?: unknown) { invokeCount += 1; },
				}];
			},
		};
		const events: Record<PropertyKey, unknown> = {};
		const handlers = new Map<string, Array<(event: any, context: any) => unknown>>();
		const pi = {
			events,
			registerCommand() {},
			registerTool() {},
			on(name: string, handler: (event: any, context: any) => unknown) {
				handlers.set(name, [...(handlers.get(name) ?? []), handler]);
			},
		};
		createExtension(pi as never);
		events[CODE_MODE_RUNTIME_KEY] = { runtime: { providers: new Map([[{}, provider]]) } };
		const context = { cwd: "/tmp", mode: "tui" };
		const toolCall = handlers.get("tool_call")![0]!;

		writeFileSync(configPath, JSON.stringify({ guards: ALL_GUARDS_DISABLED }));
		assert.equal(await toolCall({ toolName: "exec", input: { code: "dynamic" } }, context), undefined);
		const nested = provider.getTools()[0]!;

		writeFileSync(configPath, JSON.stringify({ guards: { rm: false, terraform: true } }));
		await nested.invoke({ cmd: "rm disabled" }, { cwd: "/tmp", extensionContext: context });
		assert.equal(invokeCount, 1);
		await assert.rejects(
			nested.invoke({ cmd: "rm disabled && terraform apply" }, { cwd: "/tmp", extensionContext: context }),
			/terraform apply is not on the low-risk allowlist/,
		);
		assert.equal(invokeCount, 1);

		writeFileSync(configPath, JSON.stringify({ commands: { rm: { allow: ["code-mode-target"] } } }));
		await nested.invoke({ cmd: "rm code-mode-target" }, { cwd: "/tmp", extensionContext: context });
		assert.equal(invokeCount, 2);
		writeFileSync(configPath, JSON.stringify({ commands: { rm: { requireApproval: ["code-mode-target"] } } }));
		await assert.rejects(
			nested.invoke({ cmd: "rm code-mode-target" }, { cwd: "/tmp", extensionContext: context }),
			/Custom command rule requires approval/,
		);
		assert.equal(invokeCount, 2);

		writeFileSync(configPath, JSON.stringify({ guards: { rm: "off" } }));
		await assert.rejects(
			nested.invoke({ cmd: "rm invalid-config" }, { cwd: "/tmp", extensionContext: context }),
			/rm command needs confirmation/,
		);
		assert.equal(invokeCount, 2);
	} finally {
		if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
		else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
		rmSync(directory, { recursive: true, force: true });
	}
});

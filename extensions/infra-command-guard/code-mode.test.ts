import assert from "node:assert/strict";
import {
	CODE_MODE_GUARD_BRIDGE_KEY,
	CODE_MODE_RUNTIME_KEY,
	CODE_MODE_TOOL_WRAPPED,
	ensureCodeModeGuardInstalled,
} from "./code-mode.ts";
import { test } from "./test-harness.ts";

test("Code Mode provider wrapper blocks before invoke and reads the current reload bridge", async () => {
	let invokeCount = 0;
	const provider = {
		getTools() {
			return [
				{
					name: "exec_command",
					async invoke(_input?: unknown, _context?: unknown, _signal?: AbortSignal) {
						invokeCount += 1;
						return "ran";
					},
				},
			];
		},
	};
	const events: Record<PropertyKey, unknown> = {
		[CODE_MODE_RUNTIME_KEY]: { runtime: { providers: new Map([[{}, provider]]) } },
	};
	events[CODE_MODE_GUARD_BRIDGE_KEY] = () => {
		throw new Error("blocked by test bridge");
	};

	assert.deepEqual(ensureCodeModeGuardInstalled(events, { cwd: "/tmp" }), { ok: true });
	assert.deepEqual(ensureCodeModeGuardInstalled(events, { cwd: "/tmp" }), { ok: true });
	const firstTool = provider.getTools()[0]!;
	assert.equal(Object.prototype.hasOwnProperty.call(firstTool, CODE_MODE_TOOL_WRAPPED), true);
	await assert.rejects(firstTool.invoke({ cmd: "rm target" }, { cwd: "/tmp" }), /blocked by test bridge/);
	assert.equal(invokeCount, 0);

	let bridgeCount = 0;
	events[CODE_MODE_GUARD_BRIDGE_KEY] = () => {
		bridgeCount += 1;
	};
	assert.equal(await firstTool.invoke({ cmd: "printf safe" }, { cwd: "/tmp" }), "ran");
	assert.equal(bridgeCount, 1);
	assert.equal(invokeCount, 1);

	delete events[CODE_MODE_GUARD_BRIDGE_KEY];
	await assert.rejects(firstTool.invoke({ cmd: "printf safe" }, { cwd: "/tmp" }), /bridge is unavailable/);
	assert.equal(invokeCount, 1);
});

test("Code Mode adapter guards providers added after startup", async () => {
	const calls: string[] = [];
	const createProvider = (name: string) => ({
		getTools() {
			return [
				{
					name: "exec_command",
					async invoke(_input?: unknown, _context?: unknown, _signal?: AbortSignal) {
						calls.push(name);
						return name;
					},
				},
			];
		},
	});
	const first = createProvider("first");
	const providers = new Map<object, ReturnType<typeof createProvider>>([[{}, first]]);
	const events: Record<PropertyKey, unknown> = {
		[CODE_MODE_RUNTIME_KEY]: { runtime: { providers } },
		[CODE_MODE_GUARD_BRIDGE_KEY]: () => undefined,
	};
	assert.deepEqual(ensureCodeModeGuardInstalled(events, {}), { ok: true });
	assert.equal(await first.getTools()[0]!.invoke({}, {}), "first");

	const second = createProvider("second");
	providers.set({}, second);
	assert.deepEqual(ensureCodeModeGuardInstalled(events, {}), { ok: true });
	assert.equal(await second.getTools()[0]!.invoke({}, {}), "second");
	assert.deepEqual(calls, ["first", "second"]);

});

test("Code Mode integration fails closed when private runtime internals are unavailable", () => {
	assert.deepEqual(ensureCodeModeGuardInstalled({}, { cwd: "/tmp" }), {
		ok: false,
		reason: "Code Mode runtime was not found",
	});
	assert.deepEqual(
		ensureCodeModeGuardInstalled({ [CODE_MODE_RUNTIME_KEY]: { runtime: {} } }, { cwd: "/tmp" }),
		{ ok: false, reason: "Code Mode provider registry has an unsupported shape" },
	);
	assert.deepEqual(
		ensureCodeModeGuardInstalled({ [CODE_MODE_RUNTIME_KEY]: { providers: [] } }, { cwd: "/tmp" }),
		{ ok: false, reason: "Code Mode runtime was not found" },
	);
	assert.deepEqual(
		ensureCodeModeGuardInstalled(
			{ [CODE_MODE_RUNTIME_KEY]: { runtime: { providers: new Map([[{}, { getTools: () => [] }]]) } } },
			{ cwd: "/tmp" },
		),
		{ ok: false, reason: "Code Mode nested exec_command provider was not found" },
	);
	assert.deepEqual(
		ensureCodeModeGuardInstalled(
			{
				[CODE_MODE_RUNTIME_KEY]: {
					runtime: {
						providers: new Map([
							[{}, { getTools: () => { throw new Error("provider failed"); } }],
						]),
					},
				},
			},
			{ cwd: "/tmp" },
		),
		{ ok: false, reason: "Code Mode guard installation failed: provider failed" },
	);
});

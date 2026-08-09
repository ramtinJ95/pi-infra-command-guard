import assert from "node:assert/strict";
import {
	registerCodeModeToolPreflight,
	type CodeModeToolPreflight,
} from "./code-mode.ts";
import { test } from "./test-harness.ts";

const PREFLIGHT_PROTOCOL =
	"@howaboua/pi-codex-conversion/code-mode-preflight/v1";
const PREFLIGHT_REQUEST_CHANNEL = `${PREFLIGHT_PROTOCOL}/request`;
const PREFLIGHT_AVAILABLE_CHANNEL = `${PREFLIGHT_PROTOCOL}/available`;

function createTestApis() {
	const listeners = new Map<string, Set<(data: unknown) => void>>();
	const createPi = () => {
		const shutdownHandlers: Array<() => void> = [];
		const events = {
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
		return {
			pi: {
				events,
				on(name: string, handler: () => void) {
					if (name === "session_shutdown") shutdownHandlers.push(handler);
				},
			},
			shutdown() {
				for (const handler of shutdownHandlers) handler();
			},
		};
	};
	return createPi;
}

function createBroker(pi: ReturnType<ReturnType<typeof createTestApis>>["pi"]) {
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
	const stopRequests = pi.events.on(PREFLIGHT_REQUEST_CHANNEL, (request) => {
		if (
			request &&
			typeof request === "object" &&
			"protocol" in request &&
			request.protocol === PREFLIGHT_PROTOCOL
		) pi.events.emit(PREFLIGHT_AVAILABLE_CHANNEL, broker);
	});
	pi.events.emit(PREFLIGHT_AVAILABLE_CHANNEL, broker);
	return {
		handlers,
		shutdown() {
			active = false;
			handlers.clear();
			stopRequests();
		},
	};
}

for (const order of ["broker-first", "guard-first"] as const) {
	test(`Code Mode guard uses the published preflight API across Pi 0.84 event facades (${order})`, async () => {
		const createPi = createTestApis();
		const codeMode = createPi();
		const guard = createPi();
		assert.notEqual(codeMode.pi.events, guard.pi.events);
		let broker: ReturnType<typeof createBroker>;
		const registration = registerCodeModeToolPreflight(
			guard.pi as never,
			(call) => call.toolName === "exec_command"
				? { block: true, reason: "blocked by guard" }
				: undefined,
		);
		if (order === "broker-first") {
			broker = createBroker(codeMode.pi);
			await registration.ready;
		} else {
			await registration.ready;
			assert.equal(registration.isAvailable(), false);
			broker = createBroker(codeMode.pi);
		}

		assert.equal(registration.isAvailable(), true);
		const handler = [...broker.handlers][0]!;
		const extensionContext = { cwd: "/tmp", mode: "tui" } as never;
		assert.deepEqual(
			await handler({
				toolName: "exec_command",
				toolCallId: "nested-1",
				input: { cmd: "rm target" },
				cwd: "/tmp",
				extensionContext,
				signal: new AbortController().signal,
			}),
			{ block: true, reason: "blocked by guard" },
		);
		assert.equal(
			await handler({
				toolName: "apply_patch",
				toolCallId: "nested-2",
				input: "patch",
				cwd: "/tmp",
				extensionContext,
				signal: new AbortController().signal,
			}),
			undefined,
		);

		guard.shutdown();
		assert.equal(registration.isAvailable(), false);
		assert.equal(broker.handlers.size, 0);
		broker.shutdown();
	});
}

test("Code Mode guard ignores incompatible published preflight brokers", async () => {
	const createPi = createTestApis();
	const guard = createPi();
	const registration = registerCodeModeToolPreflight(guard.pi as never, () => undefined);
	await registration.ready;
	guard.pi.events.emit(PREFLIGHT_AVAILABLE_CHANNEL, {
		protocol: "@howaboua/pi-codex-conversion/code-mode-preflight/v2",
		isActive: () => true,
		register() { return () => {}; },
	});
	assert.equal(registration.isAvailable(), false);
	guard.shutdown();
});

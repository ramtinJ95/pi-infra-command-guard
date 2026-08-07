import assert from "node:assert/strict";
import {
	PREFLIGHT_BROKER_AVAILABLE_CHANNEL,
	PREFLIGHT_BROKER_REQUEST_CHANNEL,
	registerCodeModeToolPreflight,
	type CodeModeToolPreflight,
	type CodeModeToolPreflightBroker,
} from "./code-mode.ts";
import { test } from "./test-harness.ts";

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
	const handlers = new Map<object, CodeModeToolPreflight>();
	let active = true;
	const broker: CodeModeToolPreflightBroker = {
		version: 1,
		isActive: () => active,
		register(id, handler) {
			handlers.set(id, handler);
			return () => handlers.delete(id);
		},
	};
	const stopRequests = pi.events.on(PREFLIGHT_BROKER_REQUEST_CHANNEL, (request) => {
		if (
			request &&
			typeof request === "object" &&
			"connect" in request &&
			typeof request.connect === "function"
		) request.connect(broker);
	});
	pi.events.emit(PREFLIGHT_BROKER_AVAILABLE_CHANNEL, broker);
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
	test(`Code Mode guard preflight connects through isolated Pi 0.84 event facades (${order})`, async () => {
		const createPi = createTestApis();
		const codeMode = createPi();
		const guard = createPi();
		assert.notEqual(codeMode.pi.events, guard.pi.events);
		let broker: ReturnType<typeof createBroker>;
		let registration: ReturnType<typeof registerCodeModeToolPreflight>;
		const registerGuard = () => registerCodeModeToolPreflight(
			guard.pi as never,
			(call) => call.toolName === "exec_command"
				? { block: true, reason: "blocked by guard" }
				: undefined,
		);
		if (order === "broker-first") {
			broker = createBroker(codeMode.pi);
			registration = registerGuard();
		} else {
			registration = registerGuard();
			assert.equal(registration.isAvailable(), false);
			broker = createBroker(codeMode.pi);
		}

		assert.equal(registration.isAvailable(), true);
		const handler = [...broker.handlers.values()][0]!;
		assert.deepEqual(
			await handler({
				toolName: "exec_command",
				toolCallId: "nested-1",
				input: { cmd: "rm target" },
				cwd: "/tmp",
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

test("Code Mode guard ignores incompatible preflight brokers", () => {
	const createPi = createTestApis();
	const guard = createPi();
	const registration = registerCodeModeToolPreflight(guard.pi as never, () => undefined);
	guard.pi.events.emit(PREFLIGHT_BROKER_AVAILABLE_CHANNEL, {
		version: 2,
		isActive: () => true,
		register() { return () => {}; },
	});
	assert.equal(registration.isAvailable(), false);
	guard.shutdown();
});

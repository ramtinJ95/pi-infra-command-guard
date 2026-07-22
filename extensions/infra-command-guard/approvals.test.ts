import assert from "node:assert/strict";
import { ApprovalStore, executionIdentity, guardExecution } from "./approvals.ts";
import { test } from "./test-harness.ts";

test("approval is bound to the blocked execution context and consumed once", () => {
	let now = 1_000;
	const store = new ApprovalStore(() => now, () => "request-1");
	const identity = executionIdentity(
		"code-mode-exec-command",
		{ cmd: "rm -rf build", workdir: "project", shell: "zsh", tty: false },
		"/tmp",
	)!;
	const blocked = guardExecution(store, identity, "tui");
	assert.equal(blocked.allow, false);
	assert.equal(blocked.requestId, "request-1");
	assert.match(blocked.reason, /Approval request: request-1/);

	assert.deepEqual(store.approve("request-1", identity.command, "wrong reason"), {
		ok: false,
		error: "Approval request does not match the guard reason. Do not retry the command.",
	});
	assert.deepEqual(store.approve("request-1", identity.command, "rm command needs confirmation"), { ok: true });
	assert.equal(store.consume({ ...identity, cwd: "/tmp/other" }), false);
	assert.equal(store.consume({ ...identity, shell: "bash" }), false);
	assert.equal(store.consume({ ...identity, source: "exec-command" }), false);
	assert.equal(store.consume({ ...identity, tty: true }), false);
	assert.equal(store.consume({ ...identity, login: false }), false);
	assert.equal(store.consume({ ...identity, command: `${identity.command} ` }), false);
	assert.equal(store.consume(identity), true);
	assert.equal(store.consume(identity), false);

	now += 11 * 60 * 1000;
	assert.equal(store.consume(identity), false);
});

test("approval validation rejects proactive, mismatched, cancelled, and expired grants", () => {
	let now = 10_000;
	let nextId = 0;
	const store = new ApprovalStore(() => now, () => `strict-${++nextId}`);
	const identity = executionIdentity("exec-command", { cmd: "kubectl delete pod api" }, "/tmp")!;
	assert.deepEqual(store.approve("invented", identity.command, "invented"), {
		ok: false,
		error: "Approval request is missing or expired. Retry the blocked shell call to create a new request.",
	});

	const blocked = guardExecution(store, identity, "tui");
	assert.equal(blocked.allow, false);
	const blockedRequestId = blocked.allow ? undefined : blocked.requestId;
	assert.ok(blockedRequestId);
	assert.deepEqual(store.approve(blockedRequestId, `${identity.command} `, "kubectl delete is not on the low-risk allowlist"), {
		ok: false,
		error: "Approval request does not match the exact blocked command. Do not retry the command.",
	});
	store.cancel(blockedRequestId);
	assert.deepEqual(store.approve(blockedRequestId, identity.command, "kubectl delete is not on the low-risk allowlist"), {
		ok: false,
		error: "Approval request is missing or expired. Retry the blocked shell call to create a new request.",
	});

	const expiring = guardExecution(store, identity, "tui");
	assert.equal(expiring.allow, false);
	const expiringRequestId = expiring.allow ? undefined : expiring.requestId;
	assert.ok(expiringRequestId);
	assert.deepEqual(store.approve(expiringRequestId, identity.command, "kubectl delete is not on the low-risk allowlist"), { ok: true });
	now += 11 * 60 * 1000;
	assert.equal(store.consume(identity), false);
});

test("one approval cannot authorize two concurrent identical retries", () => {
	const store = new ApprovalStore(() => 1_000, () => "parallel-request");
	const identity = executionIdentity("exec-command", { cmd: "terraform apply" }, "/tmp")!;
	const blocked = guardExecution(store, identity, "tui");
	assert.equal(blocked.allow, false);
	assert.deepEqual(
		store.approve("parallel-request", identity.command, "terraform apply is not on the low-risk allowlist"),
		{ ok: true },
	);
	assert.deepEqual([store.consume(identity), store.consume(identity)].sort(), [false, true]);
});

test("approval requests expire", () => {
	let now = 5_000;
	const store = new ApprovalStore(() => now, () => "expiring-request");
	const identity = executionIdentity("exec-command", { cmd: "rm old" }, "/tmp")!;
	guardExecution(store, identity, "tui");
	now += 11 * 60 * 1000;
	assert.deepEqual(store.approve("expiring-request", identity.command, "rm command needs confirmation"), {
		ok: false,
		error: "Approval request is missing or expired. Retry the blocked shell call to create a new request.",
	});
});

test("non-TUI calls fail closed without creating an unusable approval request", () => {
	const store = new ApprovalStore(() => 1_000, () => "must-not-be-created");
	const identity = executionIdentity("exec-command", { cmd: "rm target" }, "/tmp")!;
	const guarded = guardExecution(store, identity, "rpc");
	assert.equal(guarded.allow, false);
	assert.equal(guarded.requestId, undefined);
	assert.match(guarded.reason, /Approval is unavailable outside TUI mode/);
	assert.doesNotMatch(guarded.reason, /approve_infra_command/);
});

test("interactive interpreters are denied rather than approvable", () => {
	const store = new ApprovalStore(() => 1_000, () => "unused-request");
	for (const command of ["bash", "sudo /bin/zsh", "env python3.12", "exec node"]) {
		const identity = executionIdentity("code-mode-exec-command", { cmd: command, tty: true }, "/tmp")!;
		const guarded = guardExecution(store, identity, "tui");
		assert.equal(guarded.allow, false, command);
		assert.equal(guarded.requestId, undefined, command);
		assert.match(guarded.reason, /write_stdin input cannot be classified reliably/, command);
	}
	const nonInteractive = executionIdentity("code-mode-exec-command", { cmd: "bash -lc 'printf safe'" }, "/tmp")!;
	assert.deepEqual(guardExecution(store, nonInteractive, "tui"), { allow: true });
});

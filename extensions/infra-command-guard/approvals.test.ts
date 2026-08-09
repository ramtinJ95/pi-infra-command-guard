import assert from "node:assert/strict";
import { ApprovalStore, executionIdentity, guardExecution } from "./approvals.ts";
import { GuardBypassStore } from "./bypass.ts";
import { DEFAULT_COMMAND_POLICY_SETTINGS, DEFAULT_GUARD_SETTINGS } from "./guarded-executables.ts";
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

test("clearing approvals invalidates pending requests and unused grants", () => {
	const store = new ApprovalStore(() => 1_000, () => "config-request");
	const approvedIdentity = executionIdentity("exec-command", { cmd: "rm approved" }, "/tmp")!;
	guardExecution(store, approvedIdentity, "tui");
	assert.deepEqual(store.approve("config-request", approvedIdentity.command, "rm command needs confirmation"), { ok: true });

	const pendingIdentity = executionIdentity("exec-command", { cmd: "rm pending" }, "/tmp")!;
	store.createPending(pendingIdentity, "rm command needs confirmation");
	store.clear();
	assert.equal(store.consume(approvedIdentity), false);
	const validation = store.validate("config-request", pendingIdentity.command, "rm command needs confirmation");
	assert.equal(validation.ok, false);
	if (!validation.ok) assert.match(validation.error, /missing or expired/);
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

test("classified-dangerous-only mode skips uncertainty approvals but keeps known risks", () => {
	const store = new ApprovalStore(() => 1_000, () => "relaxed-request");
	const relaxed = { ...DEFAULT_COMMAND_POLICY_SETTINGS, guardUnclassifiedCommands: false };
	const uncertain = executionIdentity("exec-command", { cmd: 'rg -n "kubectl|vault" README.md' }, "/tmp")!;
	assert.deepEqual(guardExecution(store, uncertain, "tui", relaxed), { allow: true });

	const risky = executionIdentity("exec-command", { cmd: "kubectl delete pod api" }, "/tmp")!;
	const blocked = guardExecution(store, risky, "tui", relaxed);
	assert.equal(blocked.allow, false);
	assert.equal(blocked.requestId, "relaxed-request");
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
	const relaxed = { ...DEFAULT_COMMAND_POLICY_SETTINGS, guardUnclassifiedCommands: false };
	const relaxedInteractive = executionIdentity("code-mode-exec-command", { cmd: "bash", tty: true }, "/tmp")!;
	const relaxedGuarded = guardExecution(store, relaxedInteractive, "tui", relaxed);
	assert.equal(relaxedGuarded.allow, false);
	if (!relaxedGuarded.allow) assert.match(relaxedGuarded.reason, /write_stdin input cannot be classified reliably/);
	const disabled = Object.fromEntries(Object.keys(DEFAULT_GUARD_SETTINGS).map((key) => [key, false])) as never;
	const interactive = executionIdentity("code-mode-exec-command", { cmd: "bash", tty: true }, "/tmp")!;
	assert.deepEqual(
		guardExecution(store, interactive, "tui", { ...DEFAULT_COMMAND_POLICY_SETTINGS, guards: disabled }),
		{ allow: true },
	);
});

test("an active pause is a full policy off switch without touching approvals", () => {
	const store = new ApprovalStore(() => 1_000, () => "paused-request");
	const bypasses = new GuardBypassStore(() => 1_000);
	const identity = executionIdentity("bash", { command: "rm paused-target" }, "/tmp")!;
	assert.equal(guardExecution(store, identity, "tui", DEFAULT_COMMAND_POLICY_SETTINGS, bypasses).allow, false);
	bypasses.pause(10 * 60 * 1000);
	assert.deepEqual(guardExecution(store, identity, "tui", DEFAULT_COMMAND_POLICY_SETTINGS, bypasses), { allow: true });
	assert.deepEqual(
		guardExecution(
			store,
			executionIdentity("bash", { command: "kubectl get --raw=/api/v1" }, "/tmp")!,
			"tui",
			DEFAULT_COMMAND_POLICY_SETTINGS,
			bypasses,
		),
		{ allow: true },
		"operator pause intentionally bypasses non-bypassable command policy",
	);
});

test("interactive interpreter blocks ignore pauses and bypass rules", () => {
	const store = new ApprovalStore(() => 1_000, () => "tty-request");
	const bypasses = new GuardBypassStore(() => 1_000);
	bypasses.pause(10 * 60 * 1000);
	const identity = executionIdentity("bash", { command: "bash", tty: true }, "/tmp")!;
	const guarded = guardExecution(store, identity, "tui", DEFAULT_COMMAND_POLICY_SETTINGS, bypasses);
	assert.equal(guarded.allow, false);
	assert.match(guarded.reason, /interactive shell and interpreter sessions/);
});

test("kubeconfig bypasses cover guarded kubectl commands in the stored cwd only", () => {
	const store = new ApprovalStore(() => 1_000, () => "bypass-request");
	const bypasses = new GuardBypassStore(() => 1_000);
	const identity = executionIdentity(
		"bash",
		{ command: "kubectl --kubeconfig /tmp/kc delete pod foo" },
		"/repo",
	)!;

	const first = guardExecution(store, identity, "tui", DEFAULT_COMMAND_POLICY_SETTINGS, bypasses);
	assert.equal(first.allow, false);
	assert.deepEqual(first.bypassInfo, {
		executable: "kubectl",
		scope: { kind: "kubectl-kubeconfig", path: "/tmp/kc" },
		cwd: "/repo",
	});

	bypasses.addRule("kubectl", "/repo", { kind: "kubectl-kubeconfig", path: "/tmp/kc" }, 10 * 60 * 1000);
	assert.deepEqual(guardExecution(store, identity, "tui", DEFAULT_COMMAND_POLICY_SETTINGS, bypasses), { allow: true });
	assert.deepEqual(
		guardExecution(
			store,
			executionIdentity("bash", { command: "kubectl --kubeconfig /tmp/kc delete pod bar -n default" }, "/repo/sub")!,
			"tui",
			DEFAULT_COMMAND_POLICY_SETTINGS,
			bypasses,
		),
		{ allow: true },
	);
	assert.deepEqual(
		guardExecution(
			store,
			executionIdentity("bash", { command: "kubectl rollout restart deployment/api --kubeconfig=/tmp/kc" }, "/repo/sub")!,
			"tui",
			DEFAULT_COMMAND_POLICY_SETTINGS,
			bypasses,
		),
		{ allow: true },
		"the kubeconfig scope intentionally covers a different guarded kubectl operation",
	);
	assert.equal(
		guardExecution(
			store,
			executionIdentity("bash", { command: "kubectl --kubeconfig /tmp/kc delete pod foo" }, "/other")!,
			"tui",
			DEFAULT_COMMAND_POLICY_SETTINGS,
			bypasses,
		).allow,
		false,
	);
	assert.equal(
		guardExecution(
			store,
			executionIdentity("bash", { command: "kubectl --kubeconfig /tmp/other delete pod foo" }, "/repo")!,
			"tui",
			DEFAULT_COMMAND_POLICY_SETTINGS,
			bypasses,
		).allow,
		false,
	);
	assert.equal(
		guardExecution(
			store,
			executionIdentity(
				"bash",
				{ command: "kubectl --kubeconfig /tmp/kc delete pod foo --kubeconfig /tmp/other" },
				"/repo",
			)!,
			"tui",
			DEFAULT_COMMAND_POLICY_SETTINGS,
			bypasses,
		).allow,
		false,
		"an appended kubeconfig cannot redirect a trusted scope",
	);
	assert.equal(
		guardExecution(
			store,
			executionIdentity("bash", { command: "kubectl apply -f x.yaml" }, "/repo")!,
			"tui",
			DEFAULT_COMMAND_POLICY_SETTINGS,
			bypasses,
		).allow,
		false,
	);
	assert.equal(
		guardExecution(
			store,
			executionIdentity("bash", { command: "kubectl --kubeconfig /tmp/kc get --raw=/api/v1" }, "/repo")!,
			"tui",
			DEFAULT_COMMAND_POLICY_SETTINGS,
			bypasses,
		).allow,
		false,
		"non-bypassable kubectl capabilities stay guarded within the trusted kubeconfig",
	);
	for (const separator of ["&&", ";", "||", "|"]) {
		for (const otherRisk of ["rm other-target", "terraform apply", "vault read secret/data/test"]) {
			const compound = `kubectl --kubeconfig /tmp/kc delete pod foo ${separator} ${otherRisk}`;
			assert.equal(
				guardExecution(
					store,
					executionIdentity("bash", { command: compound }, "/repo")!,
					"tui",
					DEFAULT_COMMAND_POLICY_SETTINGS,
					bypasses,
				).allow,
				false,
				`a matching bypass must not authorize another guarded invocation: ${compound}`,
			);
		}
	}
	assert.deepEqual(
		guardExecution(
			store,
			executionIdentity(
				"bash",
				{ command: "kubectl --kubeconfig /tmp/kc delete pod foo && printf safe" },
				"/repo",
			)!,
			"tui",
			DEFAULT_COMMAND_POLICY_SETTINGS,
			bypasses,
		),
		{ allow: true },
	);
});

test("unparseable commands and non-bypassable risks never produce a bypass offer", () => {
	const store = new ApprovalStore(() => 1_000, () => "no-bypass-request");
	const bypasses = new GuardBypassStore(() => 1_000);
	const unparseable = guardExecution(
		store,
		executionIdentity("bash", { command: "kubectl delete pod foo `" }, "/repo")!,
		"tui",
		DEFAULT_COMMAND_POLICY_SETTINGS,
		bypasses,
	);
	assert.equal(unparseable.allow, false);
	assert.equal(unparseable.bypassInfo, undefined);
	const raw = guardExecution(
		store,
		executionIdentity("bash", { command: "kubectl get --raw=/api/v1" }, "/repo")!,
		"tui",
		DEFAULT_COMMAND_POLICY_SETTINGS,
		bypasses,
	);
	assert.equal(raw.allow, false);
	assert.equal(raw.bypassInfo, undefined);
});

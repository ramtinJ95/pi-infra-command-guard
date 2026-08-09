import assert from "node:assert/strict";
import { homedir } from "node:os";
import { sep } from "node:path";
import {
	GuardBypassStore,
	describeBypassScope,
	expandHomePath,
	findMatchingBypassRule,
	isPathWithin,
} from "./bypass.ts";
import { DEFAULT_COMMAND_POLICY_SETTINGS } from "./guarded-executables.ts";
import { executionIdentity } from "./approvals.ts";
import { test } from "./test-harness.ts";

const SETTINGS = DEFAULT_COMMAND_POLICY_SETTINGS;

test("expandHomePath expands home-directory path forms", () => {
	assert.equal(expandHomePath("~"), homedir());
	assert.equal(expandHomePath(`~${sep}config${sep}kc`), `${homedir()}${sep}config${sep}kc`);
	assert.equal(expandHomePath("~/config/kc"), `${homedir()}/config/kc`);
	assert.equal(expandHomePath("$HOME/config/kc"), `${homedir()}/config/kc`);
	assert.equal(expandHomePath("${HOME}/config/kc"), `${homedir()}/config/kc`);
	assert.equal(expandHomePath("/etc/hosts"), "/etc/hosts");
	assert.equal(expandHomePath("~other/file"), "~other/file");
});

test("isPathWithin accepts the directory itself and descendants only", () => {
	assert.equal(isPathWithin("/repo", "/repo"), true);
	assert.equal(isPathWithin("/repo/sub", "/repo"), true);
	assert.equal(isPathWithin("/repo-deep", "/repo"), false);
	assert.equal(isPathWithin("/re", "/repo"), false);
});

test("bypass store pause allows everything until expiry and resumes early", () => {
	let now = 1_000;
	const store = new GuardBypassStore(() => now);
	assert.equal(store.isPaused(), false);
	store.pause(10 * 60 * 1000);
	assert.equal(store.isPaused(), true);
	store.resume();
	assert.equal(store.isPaused(), false);
	store.pause(10 * 60 * 1000);
	now += 10 * 60 * 1000;
	assert.equal(store.isPaused(), false);
});

test("bypass rules match exact prefix within the stored cwd and expire", () => {
	let now = 1_000;
	const store = new GuardBypassStore(() => now);
	const prefix = { kind: "command-prefix", tokens: ["delete", "pod"] } as const;
	store.addRule("kubectl", "/repo", prefix, 10 * 60 * 1000);
	const refreshed = store.addRule("kubectl", "/repo", prefix, 30 * 60 * 1000);
	assert.equal(store.listRules().length, 1);
	assert.equal(refreshed.expiresAt, now + 30 * 60 * 1000);
	assert.equal(store.matches("kubectl", "/repo", prefix), true);
	assert.equal(store.matches("kubectl", "/repo/sub", { kind: "command-prefix", tokens: ["delete", "pod", "foo"] }), true);
	assert.equal(store.matches("kubectl", "/other", prefix), false);
	assert.equal(store.matches("kubectl", "/repo", { kind: "command-prefix", tokens: ["delete", "deployment"] }), false);
	assert.equal(store.matches("kubectl", "/repo", { kind: "command-prefix", tokens: ["delete"] }), false);
	assert.equal(store.matches("terraform", "/repo", prefix), false);
	const [rule] = store.listRules();
	assert.ok(rule);
	assert.equal(store.removeRule(rule), true);
	assert.equal(store.removeRule(rule), false);
	assert.deepEqual(store.listRules(), []);
	store.addRule("kubectl", "/repo", prefix, 10 * 60 * 1000);
	now += 10 * 60 * 1000;
	assert.equal(store.matches("kubectl", "/repo", prefix), false);
});

test("findMatchingBypassRule scopes kubectl to its normalized kubeconfig", () => {
	const identity = executionIdentity(
		"bash",
		{ command: 'kubectl --kubeconfig ~/.config/intric-dr/staging-dr-01/kubeconfig delete pod foo' },
		"/repo",
	)!;
	const match = findMatchingBypassRule(identity, SETTINGS);
	assert.ok(match);
	assert.equal(match.executable, "kubectl");
	assert.deepEqual(match.scope, {
		kind: "kubectl-kubeconfig",
		path: `${homedir()}/.config/intric-dr/staging-dr-01/kubeconfig`,
	});
	const homeVariable = findMatchingBypassRule(
		executionIdentity("bash", { command: 'kubectl --kubeconfig "$HOME/.config/kc" delete pod foo' }, "/repo")!,
		SETTINGS,
	);
	assert.deepEqual(homeVariable?.scope, { kind: "kubectl-kubeconfig", path: `${homedir()}/.config/kc` });
	const attached = findMatchingBypassRule(
		executionIdentity("bash", { command: "kubectl delete pod foo --kubeconfig=../kc" }, "/repo/sub")!,
		SETTINGS,
	);
	assert.deepEqual(attached?.scope, { kind: "kubectl-kubeconfig", path: "/repo/kc" });
});

test("kubeconfig normalization follows shell expansion provenance", () => {
	for (const command of [
		"kubectl --kubeconfig '~/kc' delete pod foo",
		'kubectl --kubeconfig "~/kc" delete pod foo',
		"kubectl --kubeconfig \\~/kc delete pod foo",
		"kubectl --kubeconfig=~/kc delete pod foo",
		"kubectl --kubeconfig '$HOME/kc' delete pod foo",
		'kubectl --kubeconfig="$HOME/kc" delete pod foo',
	]) {
		assert.equal(
			findMatchingBypassRule(executionIdentity("bash", { command }, "/repo")!, SETTINGS),
			undefined,
			command,
		);
	}
	for (const command of [
		"kubectl --kubeconfig /tmp/kc delete pod foo",
		"kubectl --kubeconfig '/tmp/kc' delete pod foo",
		"kubectl --kubeconfig=/tmp/kc delete pod foo",
		"kubectl --kubeconfig $HOME/kc delete pod foo",
		'kubectl --kubeconfig "$HOME/kc" delete pod foo',
	]) {
		const match = findMatchingBypassRule(executionIdentity("bash", { command }, "/repo")!, SETTINGS);
		assert.equal(match?.scope.kind, "kubectl-kubeconfig", command);
	}
});

test("findMatchingBypassRule matches through wrappers and compound segments", () => {
	const identity = executionIdentity(
		"bash",
		{ command: "echo ok && command kubectl --kubeconfig /tmp/kc delete pod foo | tail -1" },
		"/repo",
	)!;
	const match = findMatchingBypassRule(identity, SETTINGS);
	assert.ok(match);
	assert.deepEqual(match.scope, { kind: "kubectl-kubeconfig", path: "/tmp/kc" });
});

test("ambiguous or dynamic kubeconfig values receive no bypass offer", () => {
	for (const command of [
		"kubectl --kubeconfig /tmp/first --kubeconfig /tmp/second delete pod foo",
		'kubectl --kubeconfig "$OTHER_HOME/kc" delete pod foo',
	]) {
		const match = findMatchingBypassRule(executionIdentity("bash", { command }, "/repo")!, SETTINGS);
		assert.equal(match, undefined, command);
	}
});

test("kubeconfig scope rejects HOME overrides and uncertain effective cwd", () => {
	for (const command of [
		'HOME=/other kubectl --kubeconfig "$HOME/kc" delete pod foo',
		'env HOME=/other kubectl --kubeconfig "$HOME/kc" delete pod foo',
		"cd /other && kubectl --kubeconfig relative/kc delete pod foo",
		"pushd /other && kubectl --kubeconfig relative/kc delete pod foo",
		"env -C /other kubectl --kubeconfig relative/kc delete pod foo",
		"sudo -D /other kubectl --kubeconfig relative/kc delete pod foo",
	]) {
		assert.equal(
			findMatchingBypassRule(executionIdentity("bash", { command }, "/repo")!, SETTINGS),
			undefined,
			command,
		);
	}
});

test("kubectl option scanning stops at the argument terminator", () => {
	const command = "kubectl delete pod foo -- --kubeconfig /tmp/not-an-option";
	const match = findMatchingBypassRule(executionIdentity("bash", { command }, "/repo")!, SETTINGS);
	assert.equal(match?.scope.kind, "command-prefix");
});

test("findMatchingBypassRule refuses compound commands with multiple guarded risks", () => {
	for (const command of [
		"kubectl delete pod foo && rm other-target",
		"kubectl delete pod foo && terraform apply",
		"kubectl delete pod foo && $OTHER_COMMAND",
	]) {
		const identity = executionIdentity("bash", { command }, "/repo")!;
		assert.equal(findMatchingBypassRule(identity, SETTINGS), undefined, command);
	}
});

test("findMatchingBypassRule skips commands the static policy already allows", () => {
	const identity = executionIdentity("bash", { command: "kubectl get pods" }, "/repo")!;
	assert.equal(findMatchingBypassRule(identity, SETTINGS), undefined);
});

test("findMatchingBypassRule refuses non-bypassable risks", () => {
	const raw = executionIdentity("bash", { command: "kubectl get --raw=/api/v1" }, "/repo")!;
	assert.equal(findMatchingBypassRule(raw, SETTINGS), undefined);
});

test("findMatchingBypassRule skips unparseable commands and disabled guards", () => {
	const unparseable = executionIdentity("bash", { command: "kubectl delete pod foo `" }, "/repo")!;
	assert.equal(findMatchingBypassRule(unparseable, SETTINGS), undefined);

	const identity = executionIdentity("bash", { command: "kubectl delete pod foo" }, "/repo")!;
	assert.equal(
		findMatchingBypassRule(identity, {
			...SETTINGS,
			guards: { ...SETTINGS.guards, kubectl: false },
		}),
		undefined,
	);
});

test("bypass store describe reports active pause and rules", () => {
	const now = 1_000;
	const store = new GuardBypassStore(() => now);
	assert.deepEqual(store.describe(), []);
	store.pause(10 * 60 * 1000);
	store.addRule("kubectl", "/repo", { kind: "command-prefix", tokens: ["delete"] }, 30 * 60 * 1000);
	const lines = store.describe();
	assert.equal(lines.length, 2);
	assert.match(lines[0], /paused for 10 minutes/);
	assert.match(lines[1], /kubectl delete in \/repo — bypassed for 30 minutes/);
	assert.equal(
		describeBypassScope("kubectl", { kind: "kubectl-kubeconfig", path: "/tmp/kc" }),
		"all guarded kubectl commands using kubeconfig /tmp/kc",
	);
});

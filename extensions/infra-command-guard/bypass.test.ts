import assert from "node:assert/strict";
import { homedir } from "node:os";
import { sep } from "node:path";
import { GuardBypassStore, expandHomePath, findMatchingBypassRule, isPathWithin } from "./bypass.ts";
import { DEFAULT_COMMAND_POLICY_SETTINGS } from "./guarded-executables.ts";
import { executionIdentity } from "./approvals.ts";
import { test } from "./test-harness.ts";

const SETTINGS = DEFAULT_COMMAND_POLICY_SETTINGS;

test("expandHomePath expands ~ and ~-prefixed paths only", () => {
	assert.equal(expandHomePath("~"), homedir());
	assert.equal(expandHomePath(`~${sep}config${sep}kc`), `${homedir()}${sep}config${sep}kc`);
	assert.equal(expandHomePath("~/config/kc"), `${homedir()}/config/kc`);
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
	store.addRule("kubectl", "/repo", ["delete", "pod"], 10 * 60 * 1000);
	assert.equal(store.matches("kubectl", "/repo", ["delete", "pod"]), true);
	assert.equal(store.matches("kubectl", "/repo/sub", ["delete", "pod", "foo"]), true);
	assert.equal(store.matches("kubectl", "/other", ["delete", "pod"]), false);
	assert.equal(store.matches("kubectl", "/repo", ["delete", "deployment"]), false);
	assert.equal(store.matches("kubectl", "/repo", ["delete"]), false);
	assert.equal(store.matches("terraform", "/repo", ["delete", "pod"]), false);
	now += 10 * 60 * 1000;
	assert.equal(store.matches("kubectl", "/repo", ["delete", "pod"]), false);
});

test("findMatchingBypassRule matches the kubeconfig scenario and keeps option values", () => {
	const identity = executionIdentity(
		"bash",
		{ command: 'kubectl --kubeconfig ~/.config/intric-dr/staging-dr-01/kubeconfig delete pod foo' },
		"/repo",
	)!;
	const match = findMatchingBypassRule(identity, SETTINGS);
	assert.ok(match);
	assert.equal(match.executable, "kubectl");
	assert.deepEqual(match.normalizedPrefix, [
		"--kubeconfig",
		`${homedir()}/.config/intric-dr/staging-dr-01/kubeconfig`,
		"delete",
		"pod",
		"foo",
	]);
});

test("findMatchingBypassRule matches through wrappers and compound segments", () => {
	const identity = executionIdentity(
		"bash",
		{ command: "echo ok && command kubectl --kubeconfig /tmp/kc delete pod foo | tail -1" },
		"/repo",
	)!;
	const match = findMatchingBypassRule(identity, SETTINGS);
	assert.ok(match);
	assert.deepEqual(match.normalizedPrefix, ["--kubeconfig", "/tmp/kc", "delete", "pod", "foo"]);
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
	store.addRule("kubectl", "/repo", ["delete"], 30 * 60 * 1000);
	const lines = store.describe();
	assert.equal(lines.length, 2);
	assert.match(lines[0], /paused for 10 minutes/);
	assert.match(lines[1], /kubectl delete in \/repo — bypassed for 30 minutes/);
});

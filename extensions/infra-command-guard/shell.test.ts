import assert from "node:assert/strict";
import { evaluateCommand } from "./policy.ts";
import { parseSimpleCommands } from "./shell.ts";
import { test } from "./test-harness.ts";

function deterministicRandom(seed: number): () => number {
	let state = seed >>> 0;
	return () => {
		state += 0x6d2b79f5;
		let value = state;
		value = Math.imul(value ^ (value >>> 15), value | 1);
		value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
		return ((value ^ (value >>> 14)) >>> 0) / 0x1_0000_0000;
	};
}

test("shell parser and policy never throw for deterministic arbitrary input", () => {
	const random = deterministicRandom(0x1af2_5e11);
	const alphabet = [
		..."abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		" ",
		"\t",
		"\n",
		"\\",
		"'",
		'"',
		"`",
		..."$(){}[];&|<>#=/.-_",
	];
	for (let sample = 0; sample < 2_000; sample += 1) {
		const length = Math.floor(random() * 120);
		let command = "";
		for (let index = 0; index < length; index += 1) {
			command += alphabet[Math.floor(random() * alphabet.length)];
		}

		assert.doesNotThrow(() => parseSimpleCommands(command), command);
		const decision = evaluateCommand(command);
		assert.equal(typeof decision.allow, "boolean", command);
		if (!decision.allow) assert.ok(decision.reason.length > 0, command);
	}
});

test("semantics-preserving shell variations cannot hide guarded mutations", () => {
	const mutations = [
		{ executable: "kubectl", args: "delete pod api" },
		{ executable: "terraform", args: "apply" },
		{ executable: "helm", args: "uninstall release" },
		{ executable: "argocd", args: "app sync api" },
		{ executable: "aws", args: "ec2 terminate-instances --instance-ids i-123" },
		{ executable: "az", args: "vm delete --resource-group api --name web" },
		{ executable: "gcloud", args: "compute instances delete web --zone us-central1-a" },
		{ executable: "rm", args: "target" },
	];
	const wrappers = ["", "env ", "sudo -n ", "command ", "nohup "];
	const assignments = ["", "TRACE_ID=guard-test "];
	const suffixes = ["", " >/tmp/guard-output", " | cat", " && printf done", "; printf done"];

	for (const mutation of mutations) {
		const midpoint = Math.max(1, Math.floor(mutation.executable.length / 2));
		const executableVariants = [
			mutation.executable,
			`/usr/local/bin/${mutation.executable}`,
			`'${mutation.executable}'`,
			`${mutation.executable.slice(0, midpoint)}\"${mutation.executable.slice(midpoint)}\"`,
			`${mutation.executable.slice(0, midpoint)}\\${mutation.executable.slice(midpoint)}`,
		];

		for (const assignment of assignments) {
			for (const wrapper of wrappers) {
				for (const executable of executableVariants) {
					for (const suffix of suffixes) {
						const command = `${assignment}${wrapper}${executable} ${mutation.args}${suffix}`;
						assert.equal(evaluateCommand(command).allow, false, command);
					}
				}
			}
		}
	}
});

test("unsupported shell constructs containing guarded commands fail closed", () => {
	const commands = [
		"printf '%s' $(kubectl delete pod api)",
		"printf '%s' `terraform apply`",
		"cat <(helm uninstall release)",
		"(argocd app sync api)",
		"rm target &",
		"kubectl delete pod api <<EOF\nmanifest\nEOF",
	];

	for (const command of commands) assert.equal(evaluateCommand(command).allow, false, command);
});

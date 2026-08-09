import assert from "node:assert/strict";
import { DEFAULT_COMMAND_POLICY_SETTINGS } from "./guarded-executables.ts";
import { evaluateCommand } from "./policy.ts";
import { runTests, test } from "./test-harness.ts";

const RELAXED = { ...DEFAULT_COMMAND_POLICY_SETTINGS, guardUnclassifiedCommands: false };

test("Bash AST recovery finds known risks in real complex-script shapes", () => {
	const risky = [
		'tmp=$(mktemp); trap \'rm -f "$tmp"\' EXIT; kubectl apply --server-side -f deployment.yaml',
		`deploy() {
			current=$(kubectl get pod api -o name)
			for target in api worker; do
				kubectl patch pod "$target" --type merge -p '{"metadata":{"labels":{"managed":"true"}}}'
			done
			kubectl apply -f deployment.yaml
		}
		deploy`,
		`cleanup() { kubectl delete pod old-api; }
		cat <<'YAML' | kubectl apply -f -
		apiVersion: v1
		kind: Pod
		metadata:
		  name: api
		YAML
		cleanup`,
		"kubectl get pods | rg api && kubectl delete pod api",
		"if ; then kubectl delete pod api; fi",
		"$TOOL inspect; kubectl delete pod api",
	];

	for (const command of risky) {
		const decision = evaluateCommand(command, RELAXED);
		assert.equal(decision.allow, false, command);
		if (!decision.allow) assert.equal(decision.basis, "knownRisk", command);
	}
});

test("Bash AST recovery distinguishes executable commands from complex-script data", () => {
	const safe = [
		`tmp=$(mktemp); printf '%s\n' "kubectl apply -f docs.yaml" > "$tmp"`,
		`inspect() { kubectl get pods; printf '%s\n' 'kubectl delete pod example'; }
		for namespace in dev test; do inspect; done`,
		`cat <<'YAML'
		apiVersion: v1
		# kubectl delete pod documentation-only
		command: ["kubectl", "apply", "-f", "example.yaml"]
		YAML`,
		`value=$(printf '%s' ok) # kubectl patch pod comment-only
		printf '%s\n' "$value"`,
		`printf '%s\n' 'kubectl exec pod/api -- sh' | grep 'kubectl delete'`,
		`rg 'kubectl (apply|delete)' README.md; kubectl get pods | grep api`,
		`TOOL=kubectl; for action in apply; do $TOOL "$action"; done`,
	];

	for (const command of safe) assert.equal(evaluateCommand(command, RELAXED).allow, true, command);
	assert.equal(evaluateCommand("echo $(kubectl delete pod api)", RELAXED).allow, false);
	assert.equal(evaluateCommand("cat <<EOF\n$(kubectl patch pod api -p '{}')\nEOF", RELAXED).allow, false);
	assert.equal(evaluateCommand("kubectl(){ printf '%s\\n' safe; }; kubectl delete pod api", RELAXED).allow, true);
	assert.equal(evaluateCommand("kubectl(){ printf '%s\\n' safe; }; echo ready; kubectl delete pod api", RELAXED).allow, true);
	assert.equal(evaluateCommand("kubectl(){ printf '%s\\n' safe; }; kubectl get pods; kubectl delete pod api", RELAXED).allow, true);
	assert.equal(evaluateCommand("kubectl(){ printf '%s\\n' safe; }; /usr/bin/kubectl delete pod api", RELAXED).allow, false);
	assert.equal(evaluateCommand("kubectl(){ printf '%s\\n' safe; }; command kubectl delete pod api", RELAXED).allow, false);
	assert.equal(evaluateCommand("KUBECTL(){ printf '%s\\n' safe; }; kubectl delete pod api", RELAXED).allow, false);
	assert.equal(evaluateCommand("kubectl(){ printf '%s\\n' safe; }; unset -f kubectl; kubectl delete pod api", RELAXED).allow, false);
	assert.equal(evaluateCommand("kubectl(){ printf '%s\\n' safe; }; builtin unset -f kubectl; kubectl delete pod api", RELAXED).allow, false);
	assert.equal(evaluateCommand("kubectl(){ printf '%s\\n' safe; }; command unset -f kubectl; kubectl delete pod api", RELAXED).allow, false);
	assert.equal(evaluateCommand("kubectl(){ printf '%s\\n' safe; }; builtin eval 'unset -f kubectl'; kubectl delete pod api", RELAXED).allow, false);
	assert.equal(evaluateCommand("kubectl(){ printf '%s\\n' safe; }; command source ./functions.sh; kubectl delete pod api", RELAXED).allow, false);
	assert.equal(evaluateCommand("kubectl(){ printf '%s\\n' safe; }; trap 'unset -f kubectl' DEBUG; kubectl delete pod api", RELAXED).allow, false);
	assert.equal(evaluateCommand("kubectl(){ printf '%s\\n' safe; }; builtin trap 'unset -f kubectl' DEBUG; kubectl delete pod api", RELAXED).allow, false);
	assert.equal(evaluateCommand("trap 'unset -f kubectl' DEBUG; kubectl(){ printf safe; }; kubectl delete pod api", RELAXED).allow, false);
	assert.equal(evaluateCommand("kubectl(){ unset -f kubectl; }; kubectl; kubectl delete pod api", RELAXED).allow, false);
	assert.equal(evaluateCommand("drop(){ builtin unset -f kubectl; }; kubectl(){ printf safe; }; drop; kubectl delete pod api", RELAXED).allow, false);
	assert.equal(evaluateCommand("sudo(){ printf '%s\\n' safe; }; sudo kubectl delete pod api", RELAXED).allow, true);
	assert.equal(evaluateCommand("sudo(){ printf '%s\\n' safe; }; /usr/bin/sudo kubectl delete pod api", RELAXED).allow, false);
	assert.equal(evaluateCommand("sudo(){ printf '%s\\n' safe; }; command sudo kubectl delete pod api", RELAXED).allow, false);
	assert.equal(evaluateCommand("sudo(){ \"$@\"; }; sudo kubectl delete pod api", RELAXED).allow, false);
	assert.equal(evaluateCommand("deploy(){ \"$@\"; }; deploy kubectl delete pod api", RELAXED).allow, false);
	assert.equal(evaluateCommand("sudo(){ \"$@\"; }; sudo kubectl get pods", RELAXED).allow, true);
	assert.equal(evaluateCommand("sudo(){ printf '%s\\n' \"$@\"; }; sudo kubectl delete pod api", RELAXED).allow, true);
	assert.equal(evaluateCommand("k(){ kubectl \"$@\"; }; k delete pod api", RELAXED).allow, false);
	assert.equal(evaluateCommand("k(){ kubectl \"$@\"; }; k get pods", RELAXED).allow, true);
	assert.equal(evaluateCommand("run(){ shift; \"$@\"; }; run x kubectl delete pod api", RELAXED).allow, false);
});

test("AST-recovered invocations preserve wrappers, paths, and non-bypassable rules", () => {
	for (const command of [
		"deploy() { sudo /usr/local/bin/kubectl delete pod api; }; deploy",
		"deploy() { env KUBECONFIG=/tmp/kube kubectl exec pod/api -- sh; }; deploy",
		"render() { helm template api ./chart --post-renderer ./renderer; }; render",
		"ship() { git -c alias.deploy='!dangerous-command' deploy; }; ship",
	]) {
		assert.equal(evaluateCommand(command, RELAXED).allow, false, command);
	}
});

function createGenerator(seed: number): () => number {
	let state = seed >>> 0;
	return () => {
		state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
		return state;
	};
}

const GENERATED_CASES_PER_CATEGORY = 100;
const GENERATED_CATEGORIES = [
	"quotes",
	"comments",
	"heredocs",
	"functions",
	"substitutions",
	"loops",
	"wrappers",
	"pipelines-and-mixed",
] as const;

test("deterministic generated Bash AST corpus has zero false positives and false negatives (1600 cases)", () => {
	const random = createGenerator(0x5eedc0de);
	let safeCases = 0;
	let riskyCases = 0;
	let falsePositives = 0;
	let falseNegatives = 0;
	const riskCommands = ["apply -f app.yaml", "delete pod api", "patch pod api -p '{}'", "exec pod/api -- sh"];

	for (const category of GENERATED_CATEGORIES) {
		for (let index = 0; index < GENERATED_CASES_PER_CATEGORY; index += 1) {
			const nonce = `${category.replaceAll("-", "_")}_${random().toString(36)}`;
			const risk = riskCommands[random() % riskCommands.length];
			const safeByCategory: Record<(typeof GENERATED_CATEGORIES)[number], string> = {
				quotes: `value=$(printf '%s' ${nonce}); printf '%s\\n' "kubectl ${risk}" "$value"`,
				comments: `value=$(printf '%s' ${nonce}); # kubectl ${risk}\nprintf '%s\\n' "$value"`,
				heredocs: `value=$(printf '%s' ${nonce}); cat <<'DATA'\nkubectl ${risk}\nDATA`,
				functions: `inspect_${nonce}() { kubectl get pods; }; inspect_${nonce}`,
				substitutions: `pod=$(kubectl get pod api -o name); printf '%s\\n' "$pod" ${nonce}`,
				loops: `for item in ${nonce} other; do kubectl get pod "$item"; done`,
				wrappers: `inspect_${nonce}() { env TEST=1 /usr/bin/kubectl get pods; }; inspect_${nonce}`,
				"pipelines-and-mixed": `value=$(printf '%s' ${nonce}); kubectl get pods | rg api; printf '%s\\n' "$value"`,
			};
			const riskyByCategory: Record<(typeof GENERATED_CATEGORIES)[number], string> = {
				quotes: `value=$(printf '%s' ${nonce}); kubectl ${risk}; printf '%s\\n' "$value"`,
				comments: `# kubectl get pods\nvalue=$(printf '%s' ${nonce}); kubectl ${risk}`,
				heredocs: `cat <<'DATA' | kubectl ${risk}\nkind: Pod\nmetadata:\n  name: ${nonce}\nDATA`,
				functions: `deploy_${nonce}() { kubectl ${risk}; }; deploy_${nonce}`,
				substitutions: `result=$(kubectl ${risk}); printf '%s\\n' "$result"`,
				loops: `for item in ${nonce} other; do kubectl ${risk}; done`,
				wrappers: `deploy_${nonce}() { sudo /usr/local/bin/kubectl ${risk}; }; deploy_${nonce}`,
				"pipelines-and-mixed": `value=$(printf '%s' ${nonce}); kubectl get pods | rg api && kubectl ${risk}`,
			};

			safeCases += 1;
			riskyCases += 1;
			if (!evaluateCommand(safeByCategory[category], RELAXED).allow) falsePositives += 1;
			if (evaluateCommand(riskyByCategory[category], RELAXED).allow) falseNegatives += 1;
		}
	}

	assert.equal(falsePositives, 0, `${falsePositives}/${safeCases} generated safe scripts were blocked`);
	assert.equal(falseNegatives, 0, `${falseNegatives}/${riskyCases} generated risky scripts were allowed`);
});

if (import.meta.main) await runTests();

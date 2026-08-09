import { performance } from "node:perf_hooks";
import { DEFAULT_COMMAND_POLICY_SETTINGS } from "./guarded-executables.ts";
import { evaluateCommand } from "./policy.ts";

const WARMUP_ITERATIONS = 20_000;
const ITERATIONS = 50_000;
const ROUNDS = 11;
const RELAXED = { ...DEFAULT_COMMAND_POLICY_SETTINGS, guardUnclassifiedCommands: false };

const WORKLOADS: Record<string, string[]> = {
	"simple/safe": ["npm test", "kubectl get pods -A", "git status --short", "terraform plan"],
	"simple/risky": ["kubectl apply -f app.yaml", "kubectl delete pod api", "terraform apply", "rm -rf target"],
	"complex/safe": [
		'tmp=$(mktemp); printf "%s\\n" "$tmp"; kubectl get pods | rg api',
		'inspect(){ kubectl get pods; }; for n in a b; do printf "%s\\n" "$n"; done',
		"cat <<'EOF'\nkubectl delete pod documentation-only\nEOF",
		'printf "%s\\n" "kubectl apply -f docs.yaml"; rg "kubectl delete" README.md',
	],
	"complex/risky": [
		'tmp=$(mktemp); trap \'rm -f "$tmp"\' EXIT; kubectl apply --server-side -f app.yaml',
		'deploy(){ current=$(kubectl get pod api -o name); for n in api; do kubectl patch pod "$n" -p \'{}\'; done; }; deploy',
		"cleanup(){ kubectl delete pod old; }; cat <<'EOF' | kubectl apply -f -\nkind: Pod\nmetadata:\n  name: api\nEOF\ncleanup",
		"(kubectl get pods | rg api) && kubectl delete pod api",
	],
};

function percentile(sorted: number[], quantile: number): number {
	return sorted[Math.ceil(sorted.length * quantile) - 1];
}

function run(commands: string[], iterations: number): number {
	let allowed = 0;
	const started = performance.now();
	for (let index = 0; index < iterations; index += 1) {
		if (evaluateCommand(commands[index % commands.length], RELAXED).allow) allowed += 1;
	}
	if (allowed < 0) throw new Error("unreachable");
	return ((performance.now() - started) * 1_000_000) / iterations;
}

for (const commands of Object.values(WORKLOADS)) run(commands, WARMUP_ITERATIONS);

console.log(`warmup=${WARMUP_ITERATIONS}/category iterations=${ITERATIONS}/round rounds=${ROUNDS}`);
for (const [name, commands] of Object.entries(WORKLOADS)) {
	const samples = Array.from({ length: ROUNDS }, () => run(commands, ITERATIONS)).sort((left, right) => left - right);
	const median = percentile(samples, 0.5);
	const p95 = percentile(samples, 0.95);
	console.log(
		`${name}: median=${median.toFixed(1)} ns p95=${p95.toFixed(1)} ns throughput=${(1_000_000_000 / median).toFixed(0)}/s`,
	);
}

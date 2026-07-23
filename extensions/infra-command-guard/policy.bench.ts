import { performance } from "node:perf_hooks";
import { evaluateCommand } from "./policy.ts";

const ITERATIONS = 200_000;
const ROUNDS = 9;

const workloads = {
	"unguarded fast path": ["git status", "npm test", "rg TODO src"],
	"existing guarded reads": ["kubectl get pods", "terraform plan", "helm list", "argocd app get api"],
	"existing guarded writes": ["kubectl delete pod api", "terraform apply", "helm upgrade api ./chart", "rm -rf target"],
	"cloud CLI reads": ["aws ec2 describe-instances", "az vm list", "gcloud compute instances list"],
	"cloud CLI writes": ["aws ec2 terminate-instances", "az vm delete", "gcloud compute instances delete web"],
};

function median(values: number[]): number {
	const sorted = [...values].sort((left, right) => left - right);
	return sorted[Math.floor(sorted.length / 2)];
}

function run(commands: string[]): number {
	let allowed = 0;
	const started = performance.now();
	for (let index = 0; index < ITERATIONS; index += 1) {
		if (evaluateCommand(commands[index % commands.length]).allow) allowed += 1;
	}
	const elapsedMs = performance.now() - started;
	if (allowed < 0) throw new Error("unreachable");
	return (elapsedMs * 1_000_000) / ITERATIONS;
}

for (const commands of Object.values(workloads)) run(commands);

for (const [name, commands] of Object.entries(workloads)) {
	const samples = Array.from({ length: ROUNDS }, () => run(commands));
	console.log(`${name}: ${median(samples).toFixed(1)} ns/evaluation`);
}

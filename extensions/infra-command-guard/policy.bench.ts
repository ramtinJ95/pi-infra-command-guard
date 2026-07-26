import { performance } from "node:perf_hooks";
import { DEFAULT_COMMAND_POLICY_SETTINGS, type CommandPolicySettings } from "./guarded-executables.ts";
import { evaluateCommand } from "./policy.ts";

const ITERATIONS = 200_000;
const ROUNDS = 9;
const RELAXED_POLICY_SETTINGS = { ...DEFAULT_COMMAND_POLICY_SETTINGS, guardUnclassifiedCommands: false };
const RELAXED_UNCERTAINTY = ['rg -n "kubectl|vault" README.md', "$TOOL apply", "aws madeup inspect-resource"];

const workloads = {
	"unguarded fast path": ["npm test", "rg TODO src", "node --version"],
	"existing guarded reads": ["kubectl get pods", "terraform plan", "helm list", "argocd app get api"],
	"existing guarded writes": ["kubectl delete pod api", "terraform apply", "helm upgrade api ./chart", "rm -rf target"],
	"cloud CLI reads": ["aws ec2 describe-instances", "az vm list", "gcloud compute instances list"],
	"cloud CLI writes": ["aws ec2 terminate-instances", "az vm delete", "gcloud compute instances delete web"],
	"Docker allowed commands": ["docker ps", "docker compose up -d", "docker run nginx:latest"],
	"Docker approval commands": ["docker volume rm database", "docker exec api sh", "docker run --privileged nginx:latest"],
	"Git allowed commands": ["git status --short", "git restore --staged file.txt", "git push origin main"],
	"Git approval commands": ["git clean -fdx", "git reset --hard HEAD~1", "git push --force origin main"],
	"Vault allowed commands": ["vault status", "vault version", "vault help read"],
	"Vault approval commands": ["vault read secret/production", "vault write secret/production value=x", "vault operator seal"],
};

function median(values: number[]): number {
	const sorted = [...values].sort((left, right) => left - right);
	return sorted[Math.floor(sorted.length / 2)];
}

function run(commands: string[], settings?: CommandPolicySettings): number {
	let allowed = 0;
	const started = performance.now();
	for (let index = 0; index < ITERATIONS; index += 1) {
		if (evaluateCommand(commands[index % commands.length], settings).allow) allowed += 1;
	}
	const elapsedMs = performance.now() - started;
	if (allowed < 0) throw new Error("unreachable");
	return (elapsedMs * 1_000_000) / ITERATIONS;
}

for (const commands of Object.values(workloads)) run(commands);
run(RELAXED_UNCERTAINTY, RELAXED_POLICY_SETTINGS);

for (const [name, commands] of Object.entries(workloads)) {
	const samples = Array.from({ length: ROUNDS }, () => run(commands));
	console.log(`${name}: ${median(samples).toFixed(1)} ns/evaluation`);
}

const relaxedSamples = Array.from({ length: ROUNDS }, () => run(RELAXED_UNCERTAINTY, RELAXED_POLICY_SETTINGS));
console.log(`relaxed uncertainty: ${median(relaxedSamples).toFixed(1)} ns/evaluation`);

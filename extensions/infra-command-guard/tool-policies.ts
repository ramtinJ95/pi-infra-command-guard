import { collectPositionals, normalizeForInfraScan } from "./shell.ts";

const SAFE_KUBECTL_TOP_LEVEL = new Set([
	"api-resources",
	"api-versions",
	"describe",
	"diff",
	"explain",
	"get",
	"log",
	"logs",
	"port-forward",
	"top",
	"version",
	"wait",
]);

const SAFE_KUBECTL_NESTED = {
	auth: new Set(["can-i", "whoami"]),
	rollout: new Set(["history", "status"]),
};

const SAFE_TERRAFORM_TOP_LEVEL = new Set([
	"fmt",
	"graph",
	"init",
	"plan",
	"providers",
	"show",
	"validate",
	"version",
]);

const SAFE_TERRAFORM_NESTED = {
	state: new Set(["list", "show"]),
	workspace: new Set(["list", "select", "show"]),
};

const SAFE_HELM_TOP_LEVEL = new Set([
	"completion",
	"env",
	"help",
	"history",
	"lint",
	"list",
	"search",
	"show",
	"status",
	"template",
	"verify",
	"version",
]);

const SAFE_HELM_NESTED = {
	dependency: new Set(["list"]),
	plugin: new Set(["list"]),
	repo: new Set(["list"]),
};

const SAFE_ARGOCD_TOP_LEVEL = new Set(["completion", "help", "version"]);
const SAFE_ARGOCD_NESTED = {
	account: new Set(["can-i", "get", "list"]),
	app: new Set(["get", "history", "list", "logs", "resources", "wait"]),
	cert: new Set(["list"]),
	cluster: new Set(["get", "list"]),
	gpg: new Set(["list"]),
	proj: new Set(["get", "list"]),
	repo: new Set(["get", "list"]),
};

const KUBECTL_LEADING_BOOLEAN_OPTIONS = new Set([
	"-A",
	"--all-namespaces",
	"--disable-compression",
	"--insecure-skip-tls-verify",
	"--match-server-version",
	"--warnings-as-errors",
]);

const KUBECTL_LEADING_VALUE_OPTIONS = new Set([
	"-n",
	"--namespace",
	"-s",
	"--server",
	"--as",
	"--as-group",
	"--cache-dir",
	"--certificate-authority",
	"--client-certificate",
	"--client-key",
	"--cluster",
	"--context",
	"--kubeconfig",
	"--password",
	"--profile",
	"--profile-output",
	"--request-timeout",
	"--tls-server-name",
	"--token",
	"--user",
	"--username",
	"-v",
]);

const TERRAFORM_LEADING_BOOLEAN_OPTIONS = new Set(["-help", "--help", "-version", "--version", "-no-color"]);
const TERRAFORM_LEADING_VALUE_OPTIONS = new Set(["-chdir"]);

const HELM_LEADING_BOOLEAN_OPTIONS = new Set([
	"--debug",
	"-h",
	"--help",
	"--kube-insecure-skip-tls-verify",
]);
const HELM_LEADING_VALUE_OPTIONS = new Set([
	"--burst-limit",
	"--color",
	"--colour",
	"--content-cache",
	"--kube-apiserver",
	"--kube-as-group",
	"--kube-as-user",
	"--kube-ca-file",
	"--kube-context",
	"--kube-tls-server-name",
	"--kube-token",
	"--kubeconfig",
	"-n",
	"--namespace",
	"--qps",
	"--registry-config",
	"--repository-cache",
	"--repository-config",
]);

const ARGOCD_LEADING_BOOLEAN_OPTIONS = new Set([
	"--core",
	"--grpc-web",
	"-h",
	"--help",
	"--insecure",
	"--plaintext",
	"--port-forward",
	"--prompts-enabled",
	"--version",
]);
const ARGOCD_LEADING_VALUE_OPTIONS = new Set([
	"--argocd-context",
	"--auth-token",
	"--client-crt",
	"--client-crt-key",
	"--config",
	"--controller-name",
	"--grpc-web-root-path",
	"--header",
	"--http-retry-max",
	"--logformat",
	"--loglevel",
	"--port-forward-namespace",
	"--redis-compress",
	"--redis-haproxy-name",
	"--redis-name",
	"--repo-server-name",
	"--server",
	"--server-crt",
	"--server-name",
]);

function isSecretLikeKubectlTarget(word) {
	const normalized = String(word || "").toLowerCase();
	return normalized.split(",").some((piece) => {
		const target = piece.trim();
		return target === "secret" || target === "secrets" || target.startsWith("secret/") || target.startsWith("secrets/");
	});
}

function hasRawKubectlFlag(words) {
	return words.some((word) => word === "--raw" || word.startsWith("--raw="));
}

function isKubectlPortForwardOnlyCommand(command) {
	const normalized = normalizeForInfraScan(command).toLowerCase();
	const kubectlMentions = normalized.match(/\bkubectl\b(?=[\s;|&()<>]|$)/g) || [];
	if (kubectlMentions.length === 0) return false;
	if (/\b(?:terraform|helm|argocd|rm)\b/.test(normalized)) return false;
	const kubectlPortForwardMentions =
		normalized.match(/\bkubectl\b(?=[\s;|&()<>]|$)(?:(?!&&|\|\||[;&|\n]).)*\bport-forward\b/g) || [];
	return kubectlPortForwardMentions.length === kubectlMentions.length;
}

function requireApproval(reason: string): { allow: boolean; reason: string } {
	return { allow: false, reason };
}

function allow(): { allow: boolean; reason?: string } {
	return { allow: true };
}

function evaluateKubectl(invocation) {
	if (hasRawKubectlFlag(invocation.args)) {
		return requireApproval("kubectl --raw is not on the low-risk allowlist");
	}

	const collected = collectPositionals(invocation.args, {
		maxPositionals: 3,
		leadingBooleanOptions: KUBECTL_LEADING_BOOLEAN_OPTIONS,
		leadingValueOptions: KUBECTL_LEADING_VALUE_OPTIONS,
	});
	if (collected.error) {
		return requireApproval(`kubectl uses an unsupported flag layout (${collected.error})`);
	}

	const positionals = collected.positionals;
	const topLevel = (positionals[0] || "").toLowerCase();
	const nested = (positionals[1] || "").toLowerCase();
	const target = positionals[1] || "";

	if (!topLevel) {
		return requireApproval("kubectl command could not be classified safely");
	}

	if (topLevel === "get" || topLevel === "describe") {
		if (isSecretLikeKubectlTarget(target)) {
			return requireApproval(`kubectl ${topLevel} against secrets may expose secret material`);
		}
		return allow();
	}

	if (topLevel === "auth") {
		if (SAFE_KUBECTL_NESTED.auth.has(nested)) return allow();
		return requireApproval(`kubectl auth ${nested || "<unknown>"} is not on the low-risk allowlist`);
	}

	if (topLevel === "rollout") {
		if (SAFE_KUBECTL_NESTED.rollout.has(nested)) return allow();
		return requireApproval(`kubectl rollout ${nested || "<unknown>"} may change workload state`);
	}

	if (topLevel === "cluster-info" && nested === "dump") {
		return requireApproval("kubectl cluster-info dump can expose sensitive cluster state");
	}

	if (SAFE_KUBECTL_TOP_LEVEL.has(topLevel)) return allow();

	return requireApproval(`kubectl ${topLevel} is not on the low-risk allowlist`);
}

function evaluateTerraform(invocation) {
	const collected = collectPositionals(invocation.args, {
		maxPositionals: 2,
		leadingBooleanOptions: TERRAFORM_LEADING_BOOLEAN_OPTIONS,
		leadingValueOptions: TERRAFORM_LEADING_VALUE_OPTIONS,
	});
	if (collected.error) {
		return requireApproval(`terraform uses an unsupported flag layout (${collected.error})`);
	}

	const positionals = collected.positionals;
	const topLevel = (positionals[0] || "").toLowerCase();
	const nested = (positionals[1] || "").toLowerCase();

	if (!topLevel) {
		if (invocation.args.some((arg) => arg === "-version" || arg === "--version")) return allow();
		return requireApproval("terraform command could not be classified safely");
	}

	if (topLevel === "state") {
		if (SAFE_TERRAFORM_NESTED.state.has(nested)) return allow();
		return requireApproval(`terraform state ${nested || "<unknown>"} can mutate or rewrite state`);
	}

	if (topLevel === "workspace") {
		if (SAFE_TERRAFORM_NESTED.workspace.has(nested)) return allow();
		return requireApproval(`terraform workspace ${nested || "<unknown>"} is not on the low-risk allowlist`);
	}

	if (topLevel === "output") {
		return requireApproval("terraform output may expose sensitive values");
	}

	if (SAFE_TERRAFORM_TOP_LEVEL.has(topLevel)) return allow();

	return requireApproval(`terraform ${topLevel} is not on the low-risk allowlist`);
}

function evaluateHelm(invocation) {
	if (invocation.args.some((arg) => arg === "--post-renderer" || arg.startsWith("--post-renderer="))) {
		return requireApproval("helm --post-renderer can execute an external program");
	}

	const collected = collectPositionals(invocation.args, {
		maxPositionals: 2,
		leadingBooleanOptions: HELM_LEADING_BOOLEAN_OPTIONS,
		leadingValueOptions: HELM_LEADING_VALUE_OPTIONS,
	});
	if (collected.error) {
		return requireApproval(`helm uses an unsupported flag layout (${collected.error})`);
	}

	const topLevel = (collected.positionals[0] || "").toLowerCase();
	const nested = (collected.positionals[1] || "").toLowerCase();
	if (!topLevel) {
		if (invocation.args.some((arg) => arg === "-h" || arg === "--help")) return allow();
		return requireApproval("helm command could not be classified safely");
	}

	if (topLevel === "get") {
		return requireApproval("helm get may expose stored release values or rendered secrets");
	}

	const nestedAllowlist = SAFE_HELM_NESTED[topLevel as keyof typeof SAFE_HELM_NESTED];
	if (nestedAllowlist) {
		if (nestedAllowlist.has(nested)) return allow();
		return requireApproval(`helm ${topLevel} ${nested || "<unknown>"} is not on the low-risk allowlist`);
	}

	if (SAFE_HELM_TOP_LEVEL.has(topLevel)) return allow();
	return requireApproval(`helm ${topLevel} is not on the low-risk allowlist`);
}

function evaluateArgocd(invocation) {
	const collected = collectPositionals(invocation.args, {
		maxPositionals: 3,
		leadingBooleanOptions: ARGOCD_LEADING_BOOLEAN_OPTIONS,
		leadingValueOptions: ARGOCD_LEADING_VALUE_OPTIONS,
	});
	if (collected.error) {
		return requireApproval(`argocd uses an unsupported flag layout (${collected.error})`);
	}

	const topLevel = (collected.positionals[0] || "").toLowerCase();
	const nested = (collected.positionals[1] || "").toLowerCase();
	const action = (collected.positionals[2] || "").toLowerCase();
	if (!topLevel) {
		if (invocation.args.some((arg) => arg === "-h" || arg === "--help" || arg === "--version")) return allow();
		return requireApproval("argocd command could not be classified safely");
	}

	if (topLevel === "app" && (nested === "diff" || nested === "manifests")) {
		return requireApproval(`argocd app ${nested} may expose rendered secret material`);
	}
	if (topLevel === "app" && nested === "actions") {
		if (action === "list") return allow();
		return requireApproval(`argocd app actions ${action || "<unknown>"} may execute a resource action`);
	}

	const nestedAllowlist = SAFE_ARGOCD_NESTED[topLevel as keyof typeof SAFE_ARGOCD_NESTED];
	if (nestedAllowlist) {
		if (nestedAllowlist.has(nested)) return allow();
		return requireApproval(`argocd ${topLevel} ${nested || "<unknown>"} is not on the low-risk allowlist`);
	}

	if (SAFE_ARGOCD_TOP_LEVEL.has(topLevel)) return allow();
	return requireApproval(`argocd ${topLevel} is not on the low-risk allowlist`);
}

export {
	requireApproval,
	allow,
	isKubectlPortForwardOnlyCommand,
	evaluateKubectl,
	evaluateTerraform,
	evaluateHelm,
	evaluateArgocd,
};

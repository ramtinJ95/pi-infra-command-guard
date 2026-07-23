import { collectPositionals, normalizeForInfraScan, type Invocation } from "./shell.ts";
import { GUARDED_EXECUTABLES, type GuardedExecutable } from "./guarded-executables.ts";

type AllowDecision = { allow: true; reason?: undefined };
type ApprovalDecision = { allow: false; reason: string };
type PolicyDecision = AllowDecision | ApprovalDecision;
type ToolEvaluator = (invocation: Invocation) => PolicyDecision;

const OTHER_GUARDED_EXECUTABLE_PATTERN = new RegExp(
	`\\b(?:${GUARDED_EXECUTABLES.filter((executable) => executable !== "kubectl").join("|")})\\b`,
);
const RSYNC_DELEGATED_GUARDED_PATTERN = new RegExp(
	`\\b(?:${GUARDED_EXECUTABLES.filter((executable) => executable !== "rsync").join("|")})\\b`,
);

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

const AWS_LEADING_BOOLEAN_OPTIONS = new Set([
	"--cli-auto-prompt",
	"--debug",
	"--no-cli-auto-prompt",
	"--no-cli-pager",
	"--no-paginate",
	"--no-sign-request",
	"--no-verify-ssl",
	"--version",
]);
const AWS_LEADING_VALUE_OPTIONS = new Set([
	"--ca-bundle",
	"--cli-binary-format",
	"--cli-connect-timeout",
	"--cli-read-timeout",
	"--color",
	"--endpoint-url",
	"--error-format",
	"--output",
	"--profile",
	"--query",
	"--region",
]);

const AZ_LEADING_BOOLEAN_OPTIONS = new Set([
	"--debug",
	"--help",
	"--no-wait",
	"--only-show-errors",
	"--verbose",
	"--yes",
	"-h",
	"-y",
]);
const AZ_LEADING_VALUE_OPTIONS = new Set(["--output", "--query", "--subscription", "-o", "-s"]);

const GCLOUD_LEADING_BOOLEAN_OPTIONS = new Set([
	"--help",
	"--log-http",
	"--no-log-http",
	"--no-user-output-enabled",
	"--quiet",
	"--user-output-enabled",
	"--version",
	"-h",
	"-q",
]);
const GCLOUD_LEADING_VALUE_OPTIONS = new Set([
	"--access-token-file",
	"--account",
	"--billing-project",
	"--configuration",
	"--flatten",
	"--format",
	"--impersonate-service-account",
	"--project",
	"--trace-token",
	"--verbosity",
]);

const CLOUD_MUTATION_ACTIONS = new Set([
	"activate",
	"acquire",
	"ack",
	"add",
	"abandon",
	"apply",
	"approve",
	"assign",
	"associate",
	"attach",
	"build",
	"cancel",
	"call",
	"capture",
	"clear",
	"connect",
	"configure",
	"clone",
	"copy",
	"cp",
	"create",
	"deactivate",
	"delete",
	"deallocate",
	"decrypt",
	"deploy",
	"deprecate",
	"download",
	"drain",
	"destroy",
	"detach",
	"disable",
	"disassociate",
	"edit",
	"enable",
	"encrypt",
	"execute",
	"failover",
	"generate",
	"grant",
	"import",
	"install",
	"invoke",
	"kill",
	"lock",
	"login",
	"logout",
	"migrate",
	"modify",
	"move",
	"mv",
	"open",
	"patch",
	"pause",
	"promote",
	"publish",
	"pull",
	"purge",
	"put",
	"reboot",
	"recreate",
	"reimage",
	"release",
	"remove",
	"replace",
	"reset",
	"resize",
	"restart",
	"restore",
	"resume",
	"revoke",
	"rollback",
	"rm",
	"rsync",
	"rotate",
	"run",
	"scale",
	"send",
	"seek",
	"set",
	"sign",
	"simulate",
	"snapshot",
	"scp",
	"ssh",
	"start",
	"stop",
	"submit",
	"suspend",
	"sync",
	"terminate",
	"unassign",
	"uninstall",
	"undelete",
	"unlock",
	"update",
	"upgrade",
	"upload",
	"write",
]);

const SAFE_AZ_ACTIONS = new Set([
	"assess",
	"check",
	"exists",
	"find",
	"get",
	"list",
	"query",
	"show",
	"status",
	"tail",
	"test",
	"validate",
	"version",
	"wait",
	"what-if",
	"url",
]);
const SAFE_GCLOUD_ACTIONS = new Set([
	"cat",
	"check",
	"describe",
	"du",
	"get",
	"hash",
	"info",
	"list",
	"log",
	"logs",
	"ls",
	"print",
	"read",
	"search",
	"status",
	"tail",
	"version",
	"wait",
]);
const SAFE_AWS_EXACT_OPERATIONS = new Set([
	"describe",
	"get",
	"head",
	"help",
	"list",
	"lookup",
	"ls",
	"query",
	"scan",
	"search",
	"select",
	"status",
	"wait",
]);
const SAFE_AWS_CONFIGURE_OPERATIONS = new Set(["list", "list-profiles"]);
const SAFE_AWS_SERVICE_OPERATIONS: Readonly<Record<string, ReadonlySet<string>>> = {
	cloudformation: new Set(["estimate-template-cost"]),
	logs: new Set(["filter-log-events", "tail"]),
	rds: new Set(["download-db-log-file-portion"]),
	route53: new Set(["test-dns-answer"]),
	route53domains: new Set(["check-domain-availability"]),
	s3api: new Set(["select-object-content"]),
};
const SAFE_GCLOUD_META_COMMANDS = new Set(["completion", "help", "info", "topic", "version"]);
const AZ_MUTATION_NAMED_GROUP_PATHS = new Set(["lock", "restore-point", "snapshot"]);
const AZ_SAFE_NAMED_GROUP_PATHS = new Set([
	"internet-analyzer test",
	"load test",
	"monitor log-analytics query-pack",
	"monitor log-analytics query-pack query",
	"search",
]);
const GCLOUD_MUTATION_NAMED_GROUP_PATHS = new Set(["deploy", "run"]);
const GCLOUD_SAFE_NAMED_GROUP_PATHS = new Set(["logging logs"]);

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

const TOOL_GLOBAL_OPTIONS = {
	argocd: { boolean: ARGOCD_LEADING_BOOLEAN_OPTIONS, value: ARGOCD_LEADING_VALUE_OPTIONS },
	aws: { boolean: AWS_LEADING_BOOLEAN_OPTIONS, value: AWS_LEADING_VALUE_OPTIONS },
	az: { boolean: AZ_LEADING_BOOLEAN_OPTIONS, value: AZ_LEADING_VALUE_OPTIONS },
	find: { boolean: new Set<string>(), value: new Set<string>() },
	gcloud: { boolean: GCLOUD_LEADING_BOOLEAN_OPTIONS, value: GCLOUD_LEADING_VALUE_OPTIONS },
	helm: { boolean: HELM_LEADING_BOOLEAN_OPTIONS, value: HELM_LEADING_VALUE_OPTIONS },
	kubectl: { boolean: KUBECTL_LEADING_BOOLEAN_OPTIONS, value: KUBECTL_LEADING_VALUE_OPTIONS },
	rm: { boolean: new Set<string>(), value: new Set<string>() },
	rmdir: { boolean: new Set<string>(), value: new Set<string>() },
	rsync: { boolean: new Set<string>(), value: new Set<string>() },
	shred: { boolean: new Set<string>(), value: new Set<string>() },
	terraform: { boolean: TERRAFORM_LEADING_BOOLEAN_OPTIONS, value: TERRAFORM_LEADING_VALUE_OPTIONS },
	truncate: { boolean: new Set<string>(), value: new Set<string>() },
	unlink: { boolean: new Set<string>(), value: new Set<string>() },
} satisfies Record<GuardedExecutable, { boolean: ReadonlySet<string>; value: ReadonlySet<string> }>;
const COMMAND_LIKE_GLOBAL_OPTIONS = new Set(["-h", "--help", "-version", "--version"]);

function normalizeOverrideArguments(executable: GuardedExecutable, args: string[]): string[] {
	const options = TOOL_GLOBAL_OPTIONS[executable];
	const normalized: string[] = [];
	for (let index = 0; index < args.length; index += 1) {
		const word = args[index];
		const name = optionName(word);
		if (options.boolean.has(name)) {
			if (COMMAND_LIKE_GLOBAL_OPTIONS.has(name)) normalized.push(word);
			continue;
		}
		if (options.value.has(name)) {
			if (!word.includes("=")) index += 1;
			continue;
		}
		normalized.push(word);
	}
	return normalized;
}

function evaluateNonBypassableRisk(executable: GuardedExecutable, invocation: Invocation): PolicyDecision | undefined {
	if (executable === "kubectl" && hasRawKubectlFlag(invocation.args)) {
		return requireApproval("kubectl --raw is not on the low-risk allowlist");
	}
	if (executable === "gcloud" && hasOption(invocation.args, "--flags-file")) {
		return requireApproval("gcloud --flags-file can hide behavior from lexical classification");
	}
	if (
		executable === "helm" &&
		invocation.args.some((arg) => arg === "--post-renderer" || arg.startsWith("--post-renderer="))
	) {
		return requireApproval("helm --post-renderer can execute an external program");
	}
	if (executable === "rsync") return evaluateRsyncExecutableOptionRisk(invocation);
	return undefined;
}

function isSecretLikeKubectlTarget(word: string): boolean {
	const normalized = String(word || "").toLowerCase();
	return normalized.split(",").some((piece) => {
		const target = piece.trim();
		return target === "secret" || target === "secrets" || target.startsWith("secret/") || target.startsWith("secrets/");
	});
}

function hasRawKubectlFlag(words: string[]): boolean {
	return words.some((word) => word === "--raw" || word.startsWith("--raw="));
}

function isKubectlPortForwardOnlyCommand(command: string): boolean {
	const normalized = normalizeForInfraScan(command).toLowerCase();
	const kubectlMentions = normalized.match(/\bkubectl\b(?=[\s;|&()<>]|$)/g) || [];
	if (kubectlMentions.length === 0) return false;
	if (OTHER_GUARDED_EXECUTABLE_PATTERN.test(normalized)) return false;
	const kubectlPortForwardMentions =
		normalized.match(/\bkubectl\b(?=[\s;|&()<>]|$)(?:(?!&&|\|\||[;&|\n]).)*\bport-forward\b/g) || [];
	return kubectlPortForwardMentions.length === kubectlMentions.length;
}

function requireApproval(reason: string): ApprovalDecision {
	return { allow: false, reason };
}

function allow(): AllowDecision {
	return { allow: true };
}

function optionName(word: string): string {
	const equalsIndex = word.indexOf("=");
	return equalsIndex === -1 ? word : word.slice(0, equalsIndex);
}

const HELP_OR_VERSION_ARGUMENTS = new Set(["--help", "--version"]);
const RSYNC_DELETION_OPTIONS = new Set([
	"--del",
	"--delete",
	"--delete-after",
	"--delete-before",
	"--delete-delay",
	"--delete-during",
	"--delete-excluded",
	"--delete-missing-args",
	"--remove-sent-files",
	"--remove-source-files",
]);
const RSYNC_LONG_VALUE_OPTIONS = new Set([
	"--address", "--backup-dir", "--block-size", "--bwlimit", "--chown", "--chmod", "--compare-dest",
	"--checksum-choice", "--checksum-seed", "--compress-choice", "--compress-level", "--config", "--contimeout",
	"--copy-as", "--copy-dest", "--debug", "--early-input", "--exclude", "--exclude-from", "--files-from",
	"--filter", "--groupmap", "--iconv", "--include", "--include-from", "--info", "--link-dest", "--log-file",
	"--log-file-format", "--log-format", "--max-alloc", "--max-delete", "--max-size", "--min-size",
	"--modify-window", "--only-write-batch", "--out-format", "--partial-dir", "--password-file", "--port",
	"--protocol", "--read-batch", "--remote-option", "--rsync-path", "--rsh", "--skip-compress", "--sockopts",
	"--stderr", "--stop-after", "--stop-at", "--suffix", "--temp-dir", "--timeout", "--usermap", "--write-batch",
]);
const RSYNC_SHORT_VALUE_OPTIONS = new Set(["B", "e", "f", "M", "T"]);

function matchesRsyncLongOption(name: string, candidate: string): boolean {
	return name === candidate || (name.length >= 4 && candidate.startsWith(name));
}

function isRsyncLongValueOption(name: string): boolean {
	return [...RSYNC_LONG_VALUE_OPTIONS].some((candidate) => matchesRsyncLongOption(name, candidate));
}

function matchingRsyncDeletionOptions(option: string): string[] {
	if (RSYNC_DELETION_OPTIONS.has(option)) return [option];
	if (option.length < 4) return [];
	return [...RSYNC_DELETION_OPTIONS].filter((candidate) => candidate.startsWith(option));
}

function analyzeRsyncOptions(args: string[]): { destructive: string | undefined; dryRun: boolean } {
	let dryRun = false;
	const enabledDeletionOptions = new Set<string>();
	for (let index = 0; index < args.length; index += 1) {
		const word = args[index];
		if (word === "--") break;
		if (word.startsWith("--")) {
			const name = optionName(word);
			if (matchesRsyncLongOption(name, "--dry-run")) dryRun = true;
			if (matchesRsyncLongOption(name, "--no-dry-run")) dryRun = false;
			if (name.startsWith("--no-")) {
				const negated = matchingRsyncDeletionOptions(`--${name.slice(5)}`);
				if (negated.includes("--delete") || negated.includes("--del")) {
					for (const option of enabledDeletionOptions) {
						if (option.startsWith("--del")) enabledDeletionOptions.delete(option);
					}
				} else if (negated.some((option) => option.startsWith("--remove-"))) {
					for (const option of enabledDeletionOptions) {
						if (option.startsWith("--remove-")) enabledDeletionOptions.delete(option);
					}
				} else {
					for (const option of negated) enabledDeletionOptions.delete(option);
				}
			} else {
				for (const option of matchingRsyncDeletionOptions(name)) enabledDeletionOptions.add(option);
			}
			if (!word.includes("=") && isRsyncLongValueOption(name)) index += 1;
			continue;
		}
		if (!word.startsWith("-") || word === "-") continue;
		const shortOptions = word.slice(1);
		for (let shortIndex = 0; shortIndex < shortOptions.length; shortIndex += 1) {
			const shortOption = shortOptions[shortIndex];
			if (shortOption === "n") dryRun = true;
			if (!RSYNC_SHORT_VALUE_OPTIONS.has(shortOption)) continue;
			if (shortIndex === shortOptions.length - 1) index += 1;
			break;
		}
	}
	return { destructive: enabledDeletionOptions.values().next().value, dryRun };
}

function rsyncExecutableOptionValues(args: string[]): string[] {
	const values: string[] = [];
	for (let index = 0; index < args.length; index += 1) {
		const word = args[index];
		if (word === "--") break;
		if (word.startsWith("--")) {
			const name = optionName(word);
			if (matchesRsyncLongOption(name, "--rsh") || matchesRsyncLongOption(name, "--rsync-path")) {
				const value = word.includes("=") ? word.slice(word.indexOf("=") + 1) : args[index += 1];
				if (value !== undefined) values.push(value);
				continue;
			}
			if (!word.includes("=") && isRsyncLongValueOption(name)) index += 1;
			continue;
		}
		if (!word.startsWith("-") || word === "-") continue;
		const shortOptions = word.slice(1);
		for (let shortIndex = 0; shortIndex < shortOptions.length; shortIndex += 1) {
			const shortOption = shortOptions[shortIndex];
			if (!RSYNC_SHORT_VALUE_OPTIONS.has(shortOption)) continue;
			const attached = shortOptions.slice(shortIndex + 1).replace(/^=/, "");
			const value = attached || args[index += 1];
			if (shortOption === "e" && value !== undefined) values.push(value);
			break;
		}
	}
	return values;
}

function evaluateRsyncExecutableOptionRisk(invocation: Invocation): PolicyDecision | undefined {
	for (const executableValue of rsyncExecutableOptionValues(invocation.args)) {
		if (
			/[;&|`$()<>\r\n]/.test(executableValue) ||
			/\b(?:bash|busybox|dash|eval|exec|fish|node|perl|python|python3|ruby|sh|toybox|zsh)\b/.test(executableValue) ||
			RSYNC_DELEGATED_GUARDED_PATTERN.test(normalizeForInfraScan(executableValue).toLowerCase())
		) {
			return requireApproval("rsync executable option can run behavior hidden from command policy");
		}
	}
	return undefined;
}

function evaluateAlwaysDestructive(executable: "rmdir" | "shred" | "truncate" | "unlink", invocation: Invocation): PolicyDecision {
	if (invocation.args.length === 1 && HELP_OR_VERSION_ARGUMENTS.has(invocation.args[0])) return allow();
	return requireApproval(`${executable} command needs confirmation`);
}

function evaluateFind(invocation: Invocation): PolicyDecision {
	if (invocation.args.includes("-delete")) return requireApproval("find -delete command needs confirmation");
	return allow();
}

function evaluateRsync(invocation: Invocation): PolicyDecision {
	const executableOptionRisk = evaluateRsyncExecutableOptionRisk(invocation);
	if (executableOptionRisk) return executableOptionRisk;
	const { destructive, dryRun } = analyzeRsyncOptions(invocation.args);
	if (dryRun) return allow();
	if (destructive) return requireApproval(`rsync ${destructive} command needs confirmation`);
	return allow();
}

function actionStartsWith(action: string, candidates: ReadonlySet<string>): boolean {
	if (candidates.has(action)) return true;
	const separatorIndex = action.indexOf("-");
	return separatorIndex !== -1 && candidates.has(action.slice(0, separatorIndex));
}

function findCloudAction(
	positionals: string[],
	safeActions: ReadonlySet<string>,
	mutationNamedGroupPaths: ReadonlySet<string>,
	safeNamedGroupPaths: ReadonlySet<string>,
): { action: string; safe: boolean } | undefined {
	for (const [index, positional] of positionals.entries()) {
		const action = positional.toLowerCase();
		if (actionStartsWith(action, CLOUD_MUTATION_ACTIONS)) {
			const path = positionals.slice(0, index + 1).join(" ");
			if (mutationNamedGroupPaths.has(path)) continue;
			return { action, safe: false };
		}
		if (actionStartsWith(action, safeActions)) {
			const path = positionals.slice(0, index + 1).join(" ");
			if (safeNamedGroupPaths.has(path)) continue;
			return { action, safe: true };
		}
	}
	return undefined;
}

function hasOption(args: string[], name: string): boolean {
	return args.some((arg) => optionName(arg) === name);
}

function isSensitiveAwsRead(service: string, operation: string): boolean {
	if (service === "sts" && operation !== "get-caller-identity") return true;
	if (service === "configure" && !SAFE_AWS_CONFIGURE_OPERATIONS.has(operation)) return true;
	if (service === "secretsmanager") return true;
	if (service === "ssm" && /^(?:get-parameter|get-parameter-history|get-parameters|get-parameters-by-path)$/.test(operation)) {
		return true;
	}
	if (service === "apigateway" && operation === "get-api-key") return true;
	if (service === "lambda" && /^(?:get-function|get-function-configuration|list-functions)$/.test(operation)) return true;
	if (service === "ecs" && operation === "describe-task-definition") return true;
	if (service === "batch" && operation === "describe-job-definitions") return true;
	return /(?:access-details|access-token|authorization-token|credentials|federation-token|get-token|login-password|master-user-password|open-id-token|password-data|secret-value|session-token|signin-token|tokens-from-refresh-token)/.test(
		operation,
	);
}

function isSafeAwsOperation(service: string, operation: string): boolean {
	return (
		SAFE_AWS_SERVICE_OPERATIONS[service]?.has(operation) === true ||
		SAFE_AWS_EXACT_OPERATIONS.has(operation) ||
		/^(?:admin-get|batch-get|describe|get|head|list|lookup|search|simulate|validate)-/.test(operation)
	);
}

function evaluateAws(invocation: Invocation): PolicyDecision {
	const collected = collectPositionals(invocation.args, {
		maxPositionals: 2,
		leadingBooleanOptions: AWS_LEADING_BOOLEAN_OPTIONS,
		leadingValueOptions: AWS_LEADING_VALUE_OPTIONS,
	});
	if ("error" in collected) return requireApproval(`aws uses an unsupported flag layout (${collected.error})`);

	const service = (collected.positionals[0] || "").toLowerCase();
	const operation = (collected.positionals[1] || "").toLowerCase();
	if (!service) {
		if (hasOption(invocation.args, "--version")) return allow();
		return requireApproval("aws command could not be classified safely");
	}
	if (service === "help") return allow();
	if (!operation) return requireApproval(`aws ${service} command could not be classified safely`);
	if (isSensitiveAwsRead(service, operation)) {
		return requireApproval(`aws ${service} ${operation} may expose credentials or secret material`);
	}
	if (isSafeAwsOperation(service, operation)) return allow();
	return requireApproval(`aws ${service} ${operation} is not on the low-risk allowlist`);
}

function isSensitiveAzRead(path: string[], action: string): boolean {
	const joined = path.join(" ");
	if (/^(?:get-access-token|get-credentials|list-credentials|list-keys|list-publishing-profiles|show-connection-string)$/.test(action)) {
		return true;
	}
	if (/\bsecrets?\b/.test(joined)) return true;
	if (/\b(?:appsettings|connection-string|keys)\b/.test(joined) && actionStartsWith(action, SAFE_AZ_ACTIONS)) return true;
	if (/\bcredentials?\b/.test(joined) && actionStartsWith(action, SAFE_AZ_ACTIONS)) return true;
	return false;
}

function evaluateAz(invocation: Invocation): PolicyDecision {
	const collected = collectPositionals(invocation.args, {
		maxPositionals: 12,
		leadingBooleanOptions: AZ_LEADING_BOOLEAN_OPTIONS,
		leadingValueOptions: AZ_LEADING_VALUE_OPTIONS,
	});
	if ("error" in collected) return requireApproval(`az uses an unsupported flag layout (${collected.error})`);

	const path = collected.positionals.map((word) => word.toLowerCase());
	if (path.length === 0) {
		if (hasOption(invocation.args, "--help") || hasOption(invocation.args, "-h")) return allow();
		return requireApproval("az command could not be classified safely");
	}
	if (path[0] === "help" || path[0] === "version") return allow();

	const classified = findCloudAction(
		path,
		SAFE_AZ_ACTIONS,
		AZ_MUTATION_NAMED_GROUP_PATHS,
		AZ_SAFE_NAMED_GROUP_PATHS,
	);
	if (!classified) return requireApproval(`az ${path.join(" ")} is not on the low-risk allowlist`);
	if (!classified.safe) return requireApproval(`az ${classified.action} may change Azure or local CLI state`);
	if (isSensitiveAzRead(path, classified.action)) {
		return requireApproval(`az ${classified.action} may expose credentials or secret material`);
	}
	return allow();
}

function isSensitiveGcloudRead(path: string[], action: string): boolean {
	if (/^(?:get-credentials|print-access-token|print-identity-token)$/.test(action)) return true;
	if (path[0] === "auth" && action !== "list" && action !== "describe") return true;
	if (path[0] === "secrets") return true;
	return false;
}

function evaluateGcloud(invocation: Invocation): PolicyDecision {
	if (hasOption(invocation.args, "--flags-file")) {
		return requireApproval("gcloud --flags-file can hide behavior from lexical classification");
	}

	const collected = collectPositionals(invocation.args, {
		maxPositionals: 12,
		leadingBooleanOptions: GCLOUD_LEADING_BOOLEAN_OPTIONS,
		leadingValueOptions: GCLOUD_LEADING_VALUE_OPTIONS,
	});
	if ("error" in collected) return requireApproval(`gcloud uses an unsupported flag layout (${collected.error})`);

	const path = collected.positionals.map((word) => word.toLowerCase());
	if (path.length === 0) {
		if (hasOption(invocation.args, "--help") || hasOption(invocation.args, "-h") || hasOption(invocation.args, "--version")) {
			return allow();
		}
		return requireApproval("gcloud command could not be classified safely");
	}
	if (SAFE_GCLOUD_META_COMMANDS.has(path[0])) return allow();
	if (path[0] === "policy-troubleshoot" && path[1] === "iam") return allow();
	if (path[0] === "alpha" || path[0] === "beta") {
		return requireApproval(`gcloud ${path[0]} commands are not on the stable low-risk allowlist`);
	}

	const classified = findCloudAction(
		path,
		SAFE_GCLOUD_ACTIONS,
		GCLOUD_MUTATION_NAMED_GROUP_PATHS,
		GCLOUD_SAFE_NAMED_GROUP_PATHS,
	);
	if (!classified) return requireApproval(`gcloud ${path.join(" ")} is not on the low-risk allowlist`);
	if (!classified.safe) return requireApproval(`gcloud ${classified.action} may change Google Cloud or local CLI state`);
	if (isSensitiveGcloudRead(path, classified.action)) {
		return requireApproval(`gcloud ${classified.action} may expose credentials or secret material`);
	}
	return allow();
}

function evaluateKubectl(invocation: Invocation): PolicyDecision {
	if (hasRawKubectlFlag(invocation.args)) {
		return requireApproval("kubectl --raw is not on the low-risk allowlist");
	}

	const collected = collectPositionals(invocation.args, {
		maxPositionals: 3,
		leadingBooleanOptions: KUBECTL_LEADING_BOOLEAN_OPTIONS,
		leadingValueOptions: KUBECTL_LEADING_VALUE_OPTIONS,
	});
	if ("error" in collected) {
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

function evaluateTerraform(invocation: Invocation): PolicyDecision {
	const collected = collectPositionals(invocation.args, {
		maxPositionals: 2,
		leadingBooleanOptions: TERRAFORM_LEADING_BOOLEAN_OPTIONS,
		leadingValueOptions: TERRAFORM_LEADING_VALUE_OPTIONS,
	});
	if ("error" in collected) {
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

function evaluateHelm(invocation: Invocation): PolicyDecision {
	if (invocation.args.some((arg) => arg === "--post-renderer" || arg.startsWith("--post-renderer="))) {
		return requireApproval("helm --post-renderer can execute an external program");
	}

	const collected = collectPositionals(invocation.args, {
		maxPositionals: 2,
		leadingBooleanOptions: HELM_LEADING_BOOLEAN_OPTIONS,
		leadingValueOptions: HELM_LEADING_VALUE_OPTIONS,
	});
	if ("error" in collected) {
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

function evaluateArgocd(invocation: Invocation): PolicyDecision {
	const collected = collectPositionals(invocation.args, {
		maxPositionals: 3,
		leadingBooleanOptions: ARGOCD_LEADING_BOOLEAN_OPTIONS,
		leadingValueOptions: ARGOCD_LEADING_VALUE_OPTIONS,
	});
	if ("error" in collected) {
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
	evaluateAws,
	evaluateAz,
	evaluateFind,
	evaluateGcloud,
	evaluateRsync,
	evaluateAlwaysDestructive,
	evaluateNonBypassableRisk,
	normalizeOverrideArguments,
	rsyncExecutableOptionValues,
};
export type { AllowDecision, ApprovalDecision, PolicyDecision, ToolEvaluator };

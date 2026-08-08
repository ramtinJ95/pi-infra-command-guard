import { collectPositionals, normalizeForInfraScan, type Invocation } from "./shell.ts";
import { GUARDED_EXECUTABLES, type GuardedExecutable } from "./guarded-executables.ts";

type ApprovalBasis = "knownRisk" | "unclassified" | "explicitRule";
type AllowDecision = { allow: true; reason?: undefined; basis?: undefined };
type ApprovalDecision = { allow: false; reason: string; basis: ApprovalBasis };
type PolicyDecision = AllowDecision | ApprovalDecision;
type ToolEvaluator = (invocation: Invocation) => PolicyDecision;
type ToolGlobalOptions = Readonly<{
	boolean: ReadonlySet<string>;
	value: ReadonlySet<string>;
	attachedValue?: ReadonlySet<string>;
}>;
type ParsedLeadingCommand =
	| { command: string | null; tail: string[]; leading: string[]; error?: undefined }
	| { command?: undefined; tail?: undefined; leading?: undefined; error: string };

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
const RISKY_KUBECTL_TOP_LEVEL = new Set([
	"annotate", "apply", "attach", "autoscale", "certificate", "cordon", "cp", "create", "debug", "delete",
	"drain", "edit", "exec", "expose", "label", "patch", "replace", "run", "scale", "set", "taint", "uncordon",
]);
const RISKY_KUBECTL_ROLLOUT_ACTIONS = new Set(["pause", "restart", "resume", "undo"]);

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
const RISKY_TERRAFORM_TOP_LEVEL = new Set([
	"apply", "console", "destroy", "force-unlock", "import", "login", "logout", "refresh", "taint", "test", "untaint",
]);
const RISKY_TERRAFORM_NESTED = {
	state: new Set(["mv", "pull", "push", "replace-provider", "rm"]),
	workspace: new Set(["delete", "new"]),
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
const RISKY_HELM_TOP_LEVEL = new Set(["install", "push", "rollback", "test", "uninstall", "upgrade"]);
const RISKY_HELM_NESTED: Readonly<Record<string, ReadonlySet<string>>> = {
	dependency: new Set(["build", "update"]),
	plugin: new Set(["install", "uninstall", "update"]),
	registry: new Set(["login", "logout"]),
	repo: new Set(["add", "index", "remove", "rm", "update"]),
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
const RISKY_ARGOCD_TOP_LEVEL = new Set(["login", "logout"]);
const RISKY_ARGOCD_NESTED: Readonly<Record<string, ReadonlySet<string>>> = {
	account: new Set(["delete-token", "generate-token", "update-password"]),
	admin: new Set(["cluster", "dashboard", "export", "import", "initial-password", "notifications"]),
	app: new Set(["create", "delete", "patch", "patch-resource", "rollback", "set", "sync", "terminate-op", "unset"]),
	cluster: new Set(["add", "rm", "rotate-auth"]),
	proj: new Set(["add-destination", "add-source", "create", "delete", "remove-destination", "remove-source", "set"]),
	repo: new Set(["add", "rm"]),
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
	"authorize",
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
	"config-zip",
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
	"request",
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

const DOCKER_LEADING_BOOLEAN_OPTIONS = new Set([
	"-D",
	"--debug",
	"--help",
	"--tls",
	"--tlsverify",
	"-v",
	"--version",
]);
const DOCKER_LEADING_VALUE_OPTIONS = new Set([
	"-c",
	"--config",
	"--context",
	"-H",
	"--host",
	"-l",
	"--log-level",
	"--tlscacert",
	"--tlscert",
	"--tlskey",
]);
const DOCKER_ATTACHED_VALUE_OPTIONS = new Set(["-c", "-H", "-l"]);
const DOCKER_GLOBAL_OPTIONS: ToolGlobalOptions = {
	boolean: DOCKER_LEADING_BOOLEAN_OPTIONS,
	value: DOCKER_LEADING_VALUE_OPTIONS,
	attachedValue: DOCKER_ATTACHED_VALUE_OPTIONS,
};

const COMPOSE_LEADING_BOOLEAN_OPTIONS = new Set([
	"--all-resources",
	"--compatibility",
	"--dry-run",
	"--help",
]);
const COMPOSE_LEADING_VALUE_OPTIONS = new Set([
	"--ansi",
	"--env-file",
	"-f",
	"--file",
	"--parallel",
	"--profile",
	"--progress",
	"--project-directory",
	"-p",
	"--project-name",
]);
const COMPOSE_GLOBAL_OPTIONS: ToolGlobalOptions = {
	boolean: COMPOSE_LEADING_BOOLEAN_OPTIONS,
	value: COMPOSE_LEADING_VALUE_OPTIONS,
	attachedValue: new Set(["-f", "-p"]),
};

const GIT_LEADING_BOOLEAN_OPTIONS = new Set([
	"--bare",
	"--exec-path",
	"--glob-pathspecs",
	"-h",
	"--help",
	"--html-path",
	"--icase-pathspecs",
	"--info-path",
	"--list-cmds",
	"--literal-pathspecs",
	"--man-path",
	"--no-advice",
	"--no-lazy-fetch",
	"--no-optional-locks",
	"--no-pager",
	"--no-replace-objects",
	"--noglob-pathspecs",
	"-P",
	"-p",
	"--paginate",
	"--version",
]);
const GIT_LEADING_VALUE_OPTIONS = new Set([
	"--attr-source",
	"-C",
	"-c",
	"--config-env",
	"--git-dir",
	"--namespace",
	"--path-format",
	"--super-prefix",
	"--work-tree",
]);
const GIT_GLOBAL_OPTIONS: ToolGlobalOptions = {
	boolean: GIT_LEADING_BOOLEAN_OPTIONS,
	value: GIT_LEADING_VALUE_OPTIONS,
	attachedValue: new Set(["-C", "-c"]),
};

const VAULT_LEADING_BOOLEAN_OPTIONS = new Set([
	"-disable-redirects",
	"--disable-redirects",
	"-h",
	"-help",
	"--help",
	"-non-interactive",
	"--non-interactive",
	"-output-curl-string",
	"--output-curl-string",
	"-output-policy",
	"--output-policy",
	"-policy-override",
	"--policy-override",
	"-tls-skip-verify",
	"--tls-skip-verify",
	"-version",
	"--version",
]);
const VAULT_LEADING_VALUE_OPTIONS = new Set([
	"-address",
	"--address",
	"-agent-address",
	"--agent-address",
	"-ca-cert",
	"--ca-cert",
	"-ca-path",
	"--ca-path",
	"-client-cert",
	"--client-cert",
	"-client-key",
	"--client-key",
	"-field",
	"--field",
	"-format",
	"--format",
	"-header",
	"--header",
	"-mfa",
	"--mfa",
	"-namespace",
	"--namespace",
	"-output",
	"--output",
	"-tls-server-name",
	"--tls-server-name",
	"-token",
	"--token",
	"-wrap-ttl",
	"--wrap-ttl",
]);
const VAULT_GLOBAL_OPTIONS: ToolGlobalOptions = {
	boolean: VAULT_LEADING_BOOLEAN_OPTIONS,
	value: VAULT_LEADING_VALUE_OPTIONS,
};

const TOOL_GLOBAL_OPTIONS = {
	argocd: { boolean: ARGOCD_LEADING_BOOLEAN_OPTIONS, value: ARGOCD_LEADING_VALUE_OPTIONS },
	aws: { boolean: AWS_LEADING_BOOLEAN_OPTIONS, value: AWS_LEADING_VALUE_OPTIONS },
	az: { boolean: AZ_LEADING_BOOLEAN_OPTIONS, value: AZ_LEADING_VALUE_OPTIONS },
	docker: DOCKER_GLOBAL_OPTIONS,
	find: { boolean: new Set<string>(), value: new Set<string>() },
	gcloud: { boolean: GCLOUD_LEADING_BOOLEAN_OPTIONS, value: GCLOUD_LEADING_VALUE_OPTIONS },
	git: GIT_GLOBAL_OPTIONS,
	helm: { boolean: HELM_LEADING_BOOLEAN_OPTIONS, value: HELM_LEADING_VALUE_OPTIONS },
	kubectl: { boolean: KUBECTL_LEADING_BOOLEAN_OPTIONS, value: KUBECTL_LEADING_VALUE_OPTIONS },
	rm: { boolean: new Set<string>(), value: new Set<string>() },
	rmdir: { boolean: new Set<string>(), value: new Set<string>() },
	rsync: { boolean: new Set<string>(), value: new Set<string>() },
	shred: { boolean: new Set<string>(), value: new Set<string>() },
	terraform: { boolean: TERRAFORM_LEADING_BOOLEAN_OPTIONS, value: TERRAFORM_LEADING_VALUE_OPTIONS },
	truncate: { boolean: new Set<string>(), value: new Set<string>() },
	unlink: { boolean: new Set<string>(), value: new Set<string>() },
	vault: VAULT_GLOBAL_OPTIONS,
} satisfies Record<GuardedExecutable, ToolGlobalOptions>;
const COMMAND_LIKE_GLOBAL_OPTIONS = new Set(["-h", "--help", "-version", "--version"]);

function normalizeOverrideArguments(
	executable: GuardedExecutable,
	args: string[],
	keptValueOptions?: ReadonlySet<string>,
): string[] {
	const options = TOOL_GLOBAL_OPTIONS[executable];
	const normalized: string[] = [];
	for (let index = 0; index < args.length; index += 1) {
		const word = args[index];
		const name = optionName(word);
		if (options.boolean.has(name)) {
			if (
				COMMAND_LIKE_GLOBAL_OPTIONS.has(name) ||
				(executable === "docker" && name === "-v") ||
				(executable === "vault" && name === "-help")
			) normalized.push(word);
			continue;
		}
		if (options.value.has(name)) {
			if (keptValueOptions?.has(name)) {
				if (word.includes("=")) {
					normalized.push(word);
				} else {
					const value = args[index + 1];
					if (value === undefined) continue;
					normalized.push(word, value);
					index += 1;
				}
				continue;
			}
			if (!word.includes("=")) index += 1;
			continue;
		}
		if (hasAttachedOptionValue(word, options)) {
			continue;
		}
		normalized.push(word);
	}
	return normalized;
}

function evaluateNonBypassableRisk(executable: GuardedExecutable, invocation: Invocation): PolicyDecision | undefined {
	if (executable === "kubectl" && hasRawKubectlFlag(invocation.args)) {
		return knownRisk("kubectl --raw is not on the low-risk allowlist");
	}
	if (executable === "gcloud" && hasOption(invocation.args, "--flags-file")) {
		return unclassified("gcloud --flags-file can hide behavior from lexical classification");
	}
	if (
		executable === "helm" &&
		invocation.args.some((arg) => arg === "--post-renderer" || arg.startsWith("--post-renderer="))
	) {
		return knownRisk("helm --post-renderer can execute an external program");
	}
	if (executable === "git" && gitInlineAliasRisk(invocation.args)) {
		return knownRisk("git invocation-local aliases can hide behavior from command policy");
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

function knownRisk(reason: string): ApprovalDecision {
	return { allow: false, reason, basis: "knownRisk" };
}

function unclassified(reason: string): ApprovalDecision {
	return { allow: false, reason, basis: "unclassified" };
}

function explicitRule(reason: string): ApprovalDecision {
	return { allow: false, reason, basis: "explicitRule" };
}

function allow(): AllowDecision {
	return { allow: true };
}

function optionName(word: string): string {
	const equalsIndex = word.indexOf("=");
	return equalsIndex === -1 ? word : word.slice(0, equalsIndex);
}

function attachedOptionPrefix(word: string, options: ToolGlobalOptions): string | undefined {
	return [...(options.attachedValue ?? [])].find((prefix) => word.startsWith(prefix) && word.length > prefix.length);
}

function hasAttachedOptionValue(word: string, options: ToolGlobalOptions): boolean {
	return attachedOptionPrefix(word, options) !== undefined;
}

function parseLeadingCommand(args: readonly string[], options: ToolGlobalOptions): ParsedLeadingCommand {
	const leading: string[] = [];
	let index = 0;
	while (index < args.length) {
		const word = args[index];
		if (word === "--") {
			index += 1;
			break;
		}
		if (!word.startsWith("-") || word === "-") break;
		const name = optionName(word);
		if (options.boolean.has(name)) {
			leading.push(word);
			index += 1;
			continue;
		}
		if (options.value.has(name)) {
			leading.push(word);
			if (word.includes("=")) {
				index += 1;
				continue;
			}
			if (index + 1 >= args.length) return { error: `Missing value for option: ${word}` };
			index += 2;
			continue;
		}
		if (hasAttachedOptionValue(word, options)) {
			leading.push(word);
			index += 1;
			continue;
		}
		return { error: `Unsupported leading option: ${word}` };
	}
	if (index >= args.length) return { command: null, tail: [], leading };
	return { command: args[index], tail: args.slice(index + 1), leading };
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
			return knownRisk("rsync executable option can run behavior hidden from command policy");
		}
	}
	return undefined;
}

function evaluateAlwaysDestructive(executable: "rmdir" | "shred" | "truncate" | "unlink", invocation: Invocation): PolicyDecision {
	if (invocation.args.length === 1 && HELP_OR_VERSION_ARGUMENTS.has(invocation.args[0])) return allow();
	return knownRisk(`${executable} command needs confirmation`);
}

function evaluateFind(invocation: Invocation): PolicyDecision {
	if (invocation.args.includes("-delete")) return knownRisk("find -delete command needs confirmation");
	return allow();
}

function evaluateRsync(invocation: Invocation): PolicyDecision {
	const executableOptionRisk = evaluateRsyncExecutableOptionRisk(invocation);
	if (executableOptionRisk) return executableOptionRisk;
	const { destructive, dryRun } = analyzeRsyncOptions(invocation.args);
	if (dryRun) return allow();
	if (destructive) return knownRisk(`rsync ${destructive} command needs confirmation`);
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

function hasOption(args: readonly string[], name: string): boolean {
	return args.some((arg) => optionName(arg) === name);
}

const DOCKER_RESOURCE_REMOVAL_ACTIONS: Readonly<Record<string, ReadonlySet<string>>> = {
	container: new Set(["prune", "remove", "rm"]),
	image: new Set(["prune", "remove", "rm"]),
	network: new Set(["prune", "remove", "rm"]),
	volume: new Set(["prune", "remove", "rm"]),
	system: new Set(["prune"]),
	builder: new Set(["prune", "remove", "rm"]),
	buildx: new Set(["prune", "remove", "rm"]),
};
const DOCKER_CONTROL_PLANE_READS: Readonly<Record<string, ReadonlySet<string>>> = {
	config: new Set(["inspect", "ls"]),
	context: new Set(["inspect", "ls", "show"]),
	node: new Set(["inspect", "ls", "ps"]),
	plugin: new Set(["inspect", "ls"]),
	secret: new Set(["inspect", "ls"]),
	service: new Set(["inspect", "logs", "ls", "ps"]),
	stack: new Set(["ls", "ps", "services"]),
};
const DOCKER_READ_TOP_LEVEL = new Set([
	"diff", "events", "history", "images", "info", "inspect", "logs", "port", "ps", "search", "stats", "top", "version",
]);
const DOCKER_RESOURCE_READS: Readonly<Record<string, ReadonlySet<string>>> = {
	builder: new Set(["inspect", "ls"]),
	buildx: new Set(["du", "history", "inspect", "ls", "version"]),
	container: new Set(["diff", "inspect", "logs", "ls", "port", "stats", "top"]),
	image: new Set(["history", "inspect", "ls"]),
	network: new Set(["inspect", "ls"]),
	system: new Set(["df", "events", "info"]),
	volume: new Set(["inspect", "ls"]),
};
const SAFE_COMPOSE_READS = new Set(["config", "events", "images", "logs", "ls", "port", "ps", "top", "version", "wait"]);
const DOCKER_HOST_NAMESPACE_OPTIONS = new Set(["--cgroupns", "--ipc", "--net", "--network", "--pid", "--userns"]);
const DOCKER_HIGH_CAPABILITIES = new Set(["ALL", "DAC_READ_SEARCH", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE"]);
const DOCKER_CAPABILITY_OPTIONS = new Set(["--cap-add"]);
const DOCKER_SECURITY_OPTIONS = new Set(["--security-opt"]);
const DOCKER_VOLUME_OPTIONS = new Set(["-v", "--volume"]);
const DOCKER_ATTACHED_VOLUME_OPTIONS = new Set(["-v"]);
const DOCKER_MOUNT_OPTIONS = new Set(["--mount"]);
const DOCKER_BUILD_ENTITLEMENT_OPTIONS = new Set(["--allow"]);
const EMPTY_OPTIONS = new Set<string>();

function nestedDockerAction(tail: readonly string[]): string {
	return (tail[0] || "").toLowerCase();
}

function optionValues(args: readonly string[], names: ReadonlySet<string>, attached: ReadonlySet<string> = EMPTY_OPTIONS): string[] {
	const values: string[] = [];
	for (let index = 0; index < args.length; index += 1) {
		const word = args[index];
		if (word === "--") break;
		const name = optionName(word);
		if (names.has(name)) {
			const value = word.includes("=") ? word.slice(word.indexOf("=") + 1) : args[index += 1];
			if (value !== undefined) values.push(value);
			continue;
		}
		const prefix = [...attached].find((candidate) => word.startsWith(candidate) && word.length > candidate.length);
		if (prefix) values.push(word.slice(prefix.length).replace(/^=/, ""));
	}
	return values;
}

function hasEnabledBooleanOption(args: readonly string[], name: string): boolean {
	return args.some((word) => {
		if (word === name) return true;
		if (!word.startsWith(`${name}=`)) return false;
		return !/^(?:0|false|no)$/i.test(word.slice(name.length + 1));
	});
}

function isDockerHostRootVolume(value: string): boolean {
	return /^(?:\/|[A-Za-z]:[\\/]):/.test(value);
}

function isDockerHostRootMount(value: string): boolean {
	return /(?:source|src)=(?:\/|[A-Za-z]:[\\/])(?:,|$)/i.test(value);
}

function dockerUsesExplicitEndpoint(leading: readonly string[]): boolean {
	return leading.some((word) => {
		const name = optionName(word);
		return name === "--context" || name === "--host" || word === "-c" || word === "-H" ||
			(word.startsWith("-c") && word.length > 2) || (word.startsWith("-H") && word.length > 2);
	});
}

function dockerHostControlRisk(args: readonly string[]): string | undefined {
	if (hasEnabledBooleanOption(args, "--privileged")) return "--privileged can grant host-level control";
	if (hasOption(args, "--device") || hasOption(args, "--device-cgroup-rule")) {
		return "device access can expose host hardware to a container";
	}

	for (const value of optionValues(args, DOCKER_HOST_NAMESPACE_OPTIONS)) {
		if (value.toLowerCase() === "host") return "host namespace sharing weakens container isolation";
	}
	for (const value of optionValues(args, DOCKER_CAPABILITY_OPTIONS)) {
		if (DOCKER_HIGH_CAPABILITIES.has(value.toUpperCase())) return `--cap-add=${value} grants a high-impact kernel capability`;
	}
	for (const value of optionValues(args, DOCKER_SECURITY_OPTIONS)) {
		if (/(?:apparmor|label|seccomp).*(?:disable|unconfined)|no-new-privileges=false/i.test(value)) {
			return `--security-opt=${value} disables a container isolation control`;
		}
	}
	for (const value of optionValues(args, DOCKER_VOLUME_OPTIONS, DOCKER_ATTACHED_VOLUME_OPTIONS)) {
		if (isDockerHostRootVolume(value)) {
			return "a host-root bind mount can modify the host filesystem";
		}
		if (/(?:docker\.sock|docker_engine)/i.test(value)) return "a Docker daemon socket mount grants control of the daemon";
	}
	for (const value of optionValues(args, DOCKER_MOUNT_OPTIONS)) {
		if (isDockerHostRootMount(value)) return "a host-root bind mount can modify the host filesystem";
		if (/(?:docker\.sock|docker_engine)/i.test(value)) return "a Docker daemon socket mount grants control of the daemon";
	}
	for (const value of optionValues(args, DOCKER_BUILD_ENTITLEMENT_OPTIONS)) {
		if (/^(?:network\.host|security\.insecure)$/i.test(value)) return `--allow=${value} enables a privileged build entitlement`;
	}
	return undefined;
}

function isReadOnlyDockerCommand(topLevel: string, nested: string, composeAction: string | undefined, composeDryRun: boolean): boolean {
	if (topLevel === "compose") return composeDryRun || (composeAction !== undefined && SAFE_COMPOSE_READS.has(composeAction));
	if (DOCKER_READ_TOP_LEVEL.has(topLevel)) return true;
	if (DOCKER_RESOURCE_READS[topLevel]?.has(nested)) return true;
	if (DOCKER_CONTROL_PLANE_READS[topLevel]?.has(nested)) return true;
	return false;
}

function dockerComposeApprovalDecision(args: readonly string[]): {
	decision?: ApprovalDecision;
	action?: string;
	dryRun?: boolean;
} {
	const parsed = parseLeadingCommand(args, COMPOSE_GLOBAL_OPTIONS);
	if ("error" in parsed) {
		return { decision: unclassified(`docker compose uses an unsupported flag layout (${parsed.error})`) };
	}
	const action = (parsed.command || "").toLowerCase();
	const dryRun = parsed.leading.some((word) => optionName(word) === "--dry-run");
	if (!action || action === "help" || parsed.leading.some((word) => optionName(word) === "--help")) return { action, dryRun };
	if (action === "exec" || action === "run") {
		return { action, dryRun, decision: knownRisk(`docker compose ${action} runs an arbitrary command in a container`) };
	}
	const hostRisk = dockerHostControlRisk(parsed.tail);
	if (hostRisk) return { action, dryRun, decision: knownRisk(`docker compose ${action} ${hostRisk}`) };
	if (action === "rm") {
		return {
			action,
			dryRun,
			...(dryRun ? {} : { decision: knownRisk("docker compose rm removes service containers") }),
		};
	}
	if (
		action === "down" &&
		(
			hasOption(parsed.tail, "-v") ||
			hasEnabledBooleanOption(parsed.tail, "--volumes") ||
			hasOption(parsed.tail, "--rmi") ||
			hasEnabledBooleanOption(parsed.tail, "--remove-orphans")
		)
	) {
		return {
			action,
			dryRun,
			...(dryRun ? {} : { decision: knownRisk("docker compose down can remove volumes, images, or orphaned containers") }),
		};
	}
	if (action === "push" || action === "publish") {
		return { action, dryRun, decision: knownRisk(`docker compose ${action} writes to a registry`) };
	}
	if (hasOption(parsed.tail, "--push")) {
		return { action, dryRun, decision: knownRisk(`docker compose ${action} --push writes build output to a registry`) };
	}
	return { action, dryRun };
}

function dockerApprovalDecision(args: readonly string[]): ApprovalDecision | undefined {
	const parsed = parseLeadingCommand(args, DOCKER_GLOBAL_OPTIONS);
	if ("error" in parsed) return unclassified(`docker uses an unsupported flag layout (${parsed.error})`);
	const topLevel = (parsed.command || "").toLowerCase();
	if (!topLevel || topLevel === "help" || parsed.leading.some((word) => optionName(word) === "--help")) return undefined;
	const nested = nestedDockerAction(parsed.tail);
	let composeAction: string | undefined;
	let composeDryRun = false;
	if (topLevel === "compose") {
		const compose = dockerComposeApprovalDecision(parsed.tail);
		if (compose.decision) return compose.decision;
		composeAction = compose.action;
		composeDryRun = compose.dryRun === true;
	}

	if (topLevel === "rm" || topLevel === "rmi") return knownRisk(`docker ${topLevel} removes container data`);
	if (DOCKER_RESOURCE_REMOVAL_ACTIONS[topLevel]?.has(nested)) {
		return knownRisk(`docker ${topLevel} ${nested} removes Docker resources or data`);
	}
	if (topLevel === "exec" || topLevel === "debug" || (topLevel === "container" && nested === "exec")) {
		return knownRisk(`docker ${topLevel === "container" ? "container exec" : topLevel} runs an arbitrary command in a container`);
	}

	const hostRisk = dockerHostControlRisk(parsed.tail);
	if (hostRisk) return knownRisk(`docker ${topLevel} ${hostRisk}`);

	if (topLevel === "swarm") return knownRisk(`docker swarm ${nested || "<unknown>"} changes or exposes swarm control-plane state`);
	if (DOCKER_CONTROL_PLANE_READS[topLevel] && nested && nested !== "help" && !DOCKER_CONTROL_PLANE_READS[topLevel].has(nested)) {
		return knownRisk(`docker ${topLevel} ${nested} changes Docker control-plane state`);
	}
	if (topLevel === "login" || topLevel === "logout") return knownRisk(`docker ${topLevel} changes stored registry credentials`);
	if (topLevel === "push" || (topLevel === "image" && nested === "push") || (topLevel === "manifest" && nested === "push")) {
		return knownRisk(`docker ${topLevel}${nested ? ` ${nested}` : ""} writes to a registry`);
	}
	if (topLevel === "buildx" && nested === "imagetools" && parsed.tail[1]?.toLowerCase() === "create") {
		return knownRisk("docker buildx imagetools create writes image metadata to a registry");
	}
	if (
		(topLevel === "build" || topLevel === "builder" || topLevel === "buildx") &&
		hasOption(parsed.tail, "--push")
	) return knownRisk(`docker ${topLevel} --push writes build output to a registry`);

	if (dockerUsesExplicitEndpoint(parsed.leading) && !isReadOnlyDockerCommand(topLevel, nested, composeAction, composeDryRun)) {
		return knownRisk(`docker ${topLevel}${composeAction ? ` ${composeAction}` : ""} mutates an explicitly selected daemon`);
	}
	return undefined;
}

function evaluateDocker(invocation: Invocation): PolicyDecision {
	return dockerApprovalDecision(invocation.args) ?? allow();
}

const GIT_PUSH_VALUE_OPTIONS = new Set([
	"--exec",
	"--push-option",
	"--receive-pack",
	"--repo",
	"--server-option",
]);

function gitInlineAliasRisk(args: readonly string[]): boolean {
	for (let index = 0; index < args.length; index += 1) {
		const word = args[index];
		if (word === "--" || (!word.startsWith("-") && word !== "-")) break;
		if (word === "-c" || word === "--config-env") {
			const configValue = args[index += 1];
			if (configValue && /^alias\./i.test(configValue)) return true;
			continue;
		}
		if (word.startsWith("-c") && word.length > 2) {
			if (/^alias\./i.test(word.slice(2).replace(/^=/, ""))) return true;
			continue;
		}
		if (word.startsWith("--config-env=")) {
			if (/^alias\./i.test(word.slice("--config-env=".length))) return true;
			continue;
		}
		const name = optionName(word);
		if (GIT_LEADING_VALUE_OPTIONS.has(name) && !word.includes("=")) index += 1;
	}
	return false;
}

function hasGitShortFlag(args: readonly string[], flag: string, clusterCharacters: string): boolean {
	for (const word of args) {
		if (word === "--") break;
		if (word === `-${flag}`) return true;
		if (!/^-[^-]+$/.test(word)) continue;
		const cluster = word.slice(1);
		if ([...cluster].every((character) => clusterCharacters.includes(character)) && cluster.includes(flag)) return true;
	}
	return false;
}

function firstPositionalBeforeDelimiter(args: readonly string[]): string {
	const delimiter = args.indexOf("--");
	const candidates = delimiter === -1 ? args : args.slice(0, delimiter);
	return (candidates.find((word) => !word.startsWith("-") || word === "-") || "").toLowerCase();
}

function hasGitHelpOption(args: readonly string[]): boolean {
	for (const word of args) {
		if (word === "--") return false;
		if (word === "-h" || word === "--help") return true;
	}
	return false;
}

function gitCleanDryRun(args: readonly string[]): boolean {
	let dryRun = false;
	for (let index = 0; index < args.length; index += 1) {
		const word = args[index];
		if (word === "--") break;
		if (word === "-e" || word === "--exclude") {
			index += 1;
			continue;
		}
		if (word.startsWith("--exclude=")) continue;
		if (word === "--no-dry-run" || /^(?:--dry-run)=(?:0|false|no)$/i.test(word)) {
			dryRun = false;
			continue;
		}
		if (word === "--dry-run" || /^--dry-run=(?:1|true|yes)$/i.test(word)) {
			dryRun = true;
			continue;
		}
		if (/^-[^-]+$/.test(word)) {
			const cluster = word.slice(1);
			const excludeIndex = cluster.indexOf("e");
			const flags = excludeIndex === -1 ? cluster : cluster.slice(0, excludeIndex);
			if ([...flags].every((character) => "ndfiqxX".includes(character)) && flags.includes("n")) dryRun = true;
			if (excludeIndex !== -1 && excludeIndex === cluster.length - 1) index += 1;
		}
	}
	return dryRun;
}

function gitPruneDryRun(args: readonly string[]): boolean {
	let dryRun = false;
	for (let index = 0; index < args.length; index += 1) {
		const word = args[index];
		if (word === "--") break;
		if (word === "--expire") {
			index += 1;
			continue;
		}
		if (word.startsWith("--expire=")) continue;
		if (word === "--no-dry-run" || /^(?:--dry-run)=(?:0|false|no)$/i.test(word)) {
			dryRun = false;
			continue;
		}
		if (word === "--dry-run" || /^--dry-run=(?:1|true|yes)$/i.test(word)) {
			dryRun = true;
			continue;
		}
		if (hasGitShortFlag([word], "n", "nqv")) dryRun = true;
	}
	return dryRun;
}

function gitPushApprovalReason(args: readonly string[]): string | undefined {
	let dryRun = false;
	let repositoryOption = false;
	let flagRisk: string | undefined;
	const positionals: string[] = [];
	for (let index = 0; index < args.length; index += 1) {
		const word = args[index];
		if (word === "--") {
			positionals.push(...args.slice(index + 1));
			break;
		}
		if (word === "-o") {
			index += 1;
			continue;
		}
		if (word.startsWith("-o") && word.length > 2 && !word.startsWith("--")) continue;
		if (word.startsWith("--")) {
			const name = optionName(word);
			if (name === "--dry-run") dryRun = !/=(?:0|false|no)$/i.test(word);
			if (name === "--no-dry-run") dryRun = false;
			if (name === "--repo") repositoryOption = true;
			if (name === "--force") flagRisk = "--force";
			if (name === "--force-with-lease") flagRisk = "--force-with-lease";
			if (name === "--force-if-includes") flagRisk = "--force-if-includes";
			if (name === "--mirror") flagRisk = "--mirror";
			if (name === "--delete") flagRisk = "--delete";
			if (GIT_PUSH_VALUE_OPTIONS.has(name) && !word.includes("=")) index += 1;
			continue;
		}
		if (/^-[^-]+$/.test(word)) {
			const cluster = word.slice(1);
			if ([...cluster].every((character) => "dfnquv".includes(character))) {
				if (cluster.includes("n")) dryRun = true;
				if (cluster.includes("f")) flagRisk = "-f";
				if (cluster.includes("d")) flagRisk = "-d";
			}
			continue;
		}
		positionals.push(word);
	}
	if (dryRun) return undefined;
	if (flagRisk) return `git push ${flagRisk} can rewrite or delete remote refs`;
	const refspecs = repositoryOption ? positionals : positionals.slice(1);
	const destructiveRefspec = refspecs.find((refspec) => refspec.startsWith("+") || /^:[^:]/.test(refspec));
	return destructiveRefspec ? `git push refspec ${destructiveRefspec} can rewrite or delete remote refs` : undefined;
}

function gitApprovalDecision(args: readonly string[]): ApprovalDecision | undefined {
	if (gitInlineAliasRisk(args)) return knownRisk("git invocation-local aliases can hide behavior from command policy");
	const parsed = parseLeadingCommand(args, GIT_GLOBAL_OPTIONS);
	if ("error" in parsed) return unclassified(`git uses an unsupported global flag layout (${parsed.error})`);
	const command = (parsed.command || "").toLowerCase();
	if (!command || command === "help" || hasGitHelpOption(parsed.tail)) return undefined;

	if (command === "clean") {
		if (gitCleanDryRun(parsed.tail)) return undefined;
		return knownRisk("git clean can permanently delete untracked files");
	}
	if (command === "reset" && hasOption(parsed.tail, "--hard")) {
		return knownRisk("git reset --hard can discard working-tree and index changes");
	}
	if (command === "restore") {
		const staged = hasEnabledBooleanOption(parsed.tail, "--staged") || hasGitShortFlag(parsed.tail, "S", "SWqp");
		const worktree = hasEnabledBooleanOption(parsed.tail, "--worktree") || hasGitShortFlag(parsed.tail, "W", "SWqp");
		if (!staged || worktree) return knownRisk("git restore writes tracked content into the working tree");
	}
	if (command === "checkout") {
		if (hasEnabledBooleanOption(parsed.tail, "--force") || hasGitShortFlag(parsed.tail, "f", "qf")) {
			return knownRisk("git checkout --force can discard working-tree changes");
		}
		const delimiter = parsed.tail.indexOf("--");
		if (delimiter !== -1 && delimiter + 1 < parsed.tail.length) {
			return knownRisk("git checkout path mode overwrites working-tree files");
		}
	}
	if (
		command === "switch" &&
		(hasEnabledBooleanOption(parsed.tail, "--force") || hasEnabledBooleanOption(parsed.tail, "--discard-changes") || hasGitShortFlag(parsed.tail, "f", "qf"))
	) return knownRisk("git switch discard/force mode can discard working-tree changes");
	if (command === "branch") {
		const forcedDelete = hasGitShortFlag(parsed.tail, "D", "dDf") ||
			((hasEnabledBooleanOption(parsed.tail, "--delete") || hasGitShortFlag(parsed.tail, "d", "dDf")) &&
				(hasEnabledBooleanOption(parsed.tail, "--force") || hasGitShortFlag(parsed.tail, "f", "dDf")));
		if (forcedDelete) return knownRisk("git branch force-delete can discard an unmerged branch ref");
	}
	if (command === "tag" && (hasEnabledBooleanOption(parsed.tail, "--delete") || hasGitShortFlag(parsed.tail, "d", "dnsv"))) {
		return knownRisk("git tag deletion removes a local tag ref");
	}
	if (command === "stash") {
		const action = firstPositionalBeforeDelimiter(parsed.tail);
		if (action === "drop" || action === "clear") return knownRisk(`git stash ${action} removes saved work`);
	}
	if (command === "reflog") {
		const action = firstPositionalBeforeDelimiter(parsed.tail);
		if (action === "delete" || action === "expire") return knownRisk(`git reflog ${action} removes recovery history`);
	}
	if (
		command === "worktree" && firstPositionalBeforeDelimiter(parsed.tail) === "remove" &&
		(hasEnabledBooleanOption(parsed.tail, "--force") || hasGitShortFlag(parsed.tail, "f", "f"))
	) return knownRisk("git worktree remove --force can delete a dirty worktree");
	if (
		command === "gc" &&
		parsed.tail.some((word, index) => word === "--prune=now" || (word === "--prune" && parsed.tail[index + 1] === "now"))
	) return knownRisk("git gc --prune=now can permanently remove unreachable objects");
	if (command === "prune") {
		if (gitPruneDryRun(parsed.tail)) return undefined;
		return knownRisk("git prune can permanently remove unreachable objects");
	}
	if (command === "push") {
		const reason = gitPushApprovalReason(parsed.tail);
		return reason ? knownRisk(reason) : undefined;
	}
	return undefined;
}

function evaluateGit(invocation: Invocation): PolicyDecision {
	return gitApprovalDecision(invocation.args) ?? allow();
}

function hasVaultHelpOption(args: readonly string[]): boolean {
	const isHelp = (word: string | undefined): boolean => word === "-h" || word === "-help" || word === "--help";
	return isHelp(args[0]) || (!!args[0] && !args[0].startsWith("-") && isHelp(args[1]));
}

function vaultApprovalDecision(args: readonly string[]): ApprovalDecision | undefined {
	const parsed = parseLeadingCommand(args, VAULT_GLOBAL_OPTIONS);
	if ("error" in parsed) return unclassified(`vault uses an unsupported global flag layout (${parsed.error})`);
	const command = (parsed.command || "").toLowerCase();
	if (!command || command === "help" || command === "version" || command === "status" || hasVaultHelpOption(parsed.tail)) {
		return undefined;
	}
	const nested = firstPositionalBeforeDelimiter(parsed.tail);
	if (
		command === "read" || command === "list" || command === "unwrap" ||
		(command === "kv" && (nested === "get" || nested === "list"))
	) return knownRisk(`vault ${command}${nested ? ` ${nested}` : ""} may expose secret material`);
	if (command === "write" || command === "delete" || command === "kv") {
		return knownRisk(`vault ${command}${nested ? ` ${nested}` : ""} changes Vault data or configuration`);
	}
	if (["auth", "login", "operator", "policy", "secrets", "token"].includes(command)) {
		return knownRisk(`vault ${command}${nested ? ` ${nested}` : ""} accesses or changes security-critical Vault state`);
	}
	if (command === "agent" || command === "server") {
		return knownRisk(`vault ${command} starts a long-running secret-handling process`);
	}
	return unclassified(`vault ${command} is not on the low-risk allowlist`);
}

function evaluateVault(invocation: Invocation): PolicyDecision {
	return vaultApprovalDecision(invocation.args) ?? allow();
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
	if ("error" in collected) return unclassified(`aws uses an unsupported flag layout (${collected.error})`);

	const service = (collected.positionals[0] || "").toLowerCase();
	const operation = (collected.positionals[1] || "").toLowerCase();
	if (!service) {
		if (hasOption(invocation.args, "--version")) return allow();
		return unclassified("aws command could not be classified safely");
	}
	if (service === "help") return allow();
	if (!operation) return unclassified(`aws ${service} command could not be classified safely`);
	if (isSensitiveAwsRead(service, operation)) {
		return knownRisk(`aws ${service} ${operation} may expose credentials or secret material`);
	}
	if (isSafeAwsOperation(service, operation)) return allow();
	if (actionStartsWith(operation, CLOUD_MUTATION_ACTIONS)) {
		return knownRisk(`aws ${service} ${operation} is not on the low-risk allowlist`);
	}
	return unclassified(`aws ${service} ${operation} is not on the low-risk allowlist`);
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
	if ("error" in collected) return unclassified(`az uses an unsupported flag layout (${collected.error})`);

	const path = collected.positionals.map((word) => word.toLowerCase());
	if (path.length === 0) {
		if (hasOption(invocation.args, "--help") || hasOption(invocation.args, "-h")) return allow();
		return unclassified("az command could not be classified safely");
	}
	if (path[0] === "help" || path[0] === "version") return allow();

	const classified = findCloudAction(
		path,
		SAFE_AZ_ACTIONS,
		AZ_MUTATION_NAMED_GROUP_PATHS,
		AZ_SAFE_NAMED_GROUP_PATHS,
	);
	if (!classified) return unclassified(`az ${path.join(" ")} is not on the low-risk allowlist`);
	if (!classified.safe) return knownRisk(`az ${classified.action} may change Azure or local CLI state`);
	if (isSensitiveAzRead(path, classified.action)) {
		return knownRisk(`az ${classified.action} may expose credentials or secret material`);
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
		return unclassified("gcloud --flags-file can hide behavior from lexical classification");
	}

	const collected = collectPositionals(invocation.args, {
		maxPositionals: 12,
		leadingBooleanOptions: GCLOUD_LEADING_BOOLEAN_OPTIONS,
		leadingValueOptions: GCLOUD_LEADING_VALUE_OPTIONS,
	});
	if ("error" in collected) return unclassified(`gcloud uses an unsupported flag layout (${collected.error})`);

	const path = collected.positionals.map((word) => word.toLowerCase());
	if (path.length === 0) {
		if (hasOption(invocation.args, "--help") || hasOption(invocation.args, "-h") || hasOption(invocation.args, "--version")) {
			return allow();
		}
		return unclassified("gcloud command could not be classified safely");
	}
	if (SAFE_GCLOUD_META_COMMANDS.has(path[0])) return allow();
	if (path[0] === "policy-troubleshoot" && path[1] === "iam") return allow();
	if (path[0] === "alpha" || path[0] === "beta") {
		return unclassified(`gcloud ${path[0]} commands are not on the stable low-risk allowlist`);
	}
	if (path[0] === "secrets") {
		return knownRisk(`gcloud ${path.at(-1) || "<unknown>"} may expose credentials or secret material`);
	}

	const classified = findCloudAction(
		path,
		SAFE_GCLOUD_ACTIONS,
		GCLOUD_MUTATION_NAMED_GROUP_PATHS,
		GCLOUD_SAFE_NAMED_GROUP_PATHS,
	);
	if (!classified) return unclassified(`gcloud ${path.join(" ")} is not on the low-risk allowlist`);
	if (!classified.safe) return knownRisk(`gcloud ${classified.action} may change Google Cloud or local CLI state`);
	if (isSensitiveGcloudRead(path, classified.action)) {
		return knownRisk(`gcloud ${classified.action} may expose credentials or secret material`);
	}
	return allow();
}

function evaluateKubectl(invocation: Invocation): PolicyDecision {
	if (hasRawKubectlFlag(invocation.args)) {
		return knownRisk("kubectl --raw is not on the low-risk allowlist");
	}

	const collected = collectPositionals(invocation.args, {
		maxPositionals: 3,
		leadingBooleanOptions: KUBECTL_LEADING_BOOLEAN_OPTIONS,
		leadingValueOptions: KUBECTL_LEADING_VALUE_OPTIONS,
	});
	if ("error" in collected) {
		return unclassified(`kubectl uses an unsupported flag layout (${collected.error})`);
	}

	const positionals = collected.positionals;
	const topLevel = (positionals[0] || "").toLowerCase();
	const nested = (positionals[1] || "").toLowerCase();
	const target = positionals[1] || "";

	if (!topLevel) {
		return unclassified("kubectl command could not be classified safely");
	}

	if (topLevel === "get" || topLevel === "describe") {
		if (isSecretLikeKubectlTarget(target)) {
			return knownRisk(`kubectl ${topLevel} against secrets may expose secret material`);
		}
		return allow();
	}

	if (topLevel === "auth") {
		if (SAFE_KUBECTL_NESTED.auth.has(nested)) return allow();
		return unclassified(`kubectl auth ${nested || "<unknown>"} is not on the low-risk allowlist`);
	}

	if (topLevel === "rollout") {
		if (SAFE_KUBECTL_NESTED.rollout.has(nested)) return allow();
		if (RISKY_KUBECTL_ROLLOUT_ACTIONS.has(nested)) {
			return knownRisk(`kubectl rollout ${nested} may change workload state`);
		}
		return unclassified(`kubectl rollout ${nested || "<unknown>"} is not on the low-risk allowlist`);
	}

	if (topLevel === "cluster-info" && nested === "dump") {
		return knownRisk("kubectl cluster-info dump can expose sensitive cluster state");
	}

	if (SAFE_KUBECTL_TOP_LEVEL.has(topLevel)) return allow();
	if (RISKY_KUBECTL_TOP_LEVEL.has(topLevel)) {
		return knownRisk(`kubectl ${topLevel} is not on the low-risk allowlist`);
	}
	return unclassified(`kubectl ${topLevel} is not on the low-risk allowlist`);
}

function evaluateTerraform(invocation: Invocation): PolicyDecision {
	const collected = collectPositionals(invocation.args, {
		maxPositionals: 2,
		leadingBooleanOptions: TERRAFORM_LEADING_BOOLEAN_OPTIONS,
		leadingValueOptions: TERRAFORM_LEADING_VALUE_OPTIONS,
	});
	if ("error" in collected) {
		return unclassified(`terraform uses an unsupported flag layout (${collected.error})`);
	}

	const positionals = collected.positionals;
	const topLevel = (positionals[0] || "").toLowerCase();
	const nested = (positionals[1] || "").toLowerCase();

	if (!topLevel) {
		if (invocation.args.some((arg) => arg === "-version" || arg === "--version")) return allow();
		return unclassified("terraform command could not be classified safely");
	}

	if (topLevel === "state") {
		if (SAFE_TERRAFORM_NESTED.state.has(nested)) return allow();
		if (RISKY_TERRAFORM_NESTED.state.has(nested)) {
			return knownRisk(`terraform state ${nested} can mutate or rewrite state`);
		}
		return unclassified(`terraform state ${nested || "<unknown>"} is not on the low-risk allowlist`);
	}

	if (topLevel === "workspace") {
		if (SAFE_TERRAFORM_NESTED.workspace.has(nested)) return allow();
		if (RISKY_TERRAFORM_NESTED.workspace.has(nested)) {
			return knownRisk(`terraform workspace ${nested} is not on the low-risk allowlist`);
		}
		return unclassified(`terraform workspace ${nested || "<unknown>"} is not on the low-risk allowlist`);
	}

	if (topLevel === "output") {
		return knownRisk("terraform output may expose sensitive values");
	}

	if (SAFE_TERRAFORM_TOP_LEVEL.has(topLevel)) return allow();
	if (RISKY_TERRAFORM_TOP_LEVEL.has(topLevel)) {
		return knownRisk(`terraform ${topLevel} is not on the low-risk allowlist`);
	}
	return unclassified(`terraform ${topLevel} is not on the low-risk allowlist`);
}

function evaluateHelm(invocation: Invocation): PolicyDecision {
	if (invocation.args.some((arg) => arg === "--post-renderer" || arg.startsWith("--post-renderer="))) {
		return knownRisk("helm --post-renderer can execute an external program");
	}

	const collected = collectPositionals(invocation.args, {
		maxPositionals: 2,
		leadingBooleanOptions: HELM_LEADING_BOOLEAN_OPTIONS,
		leadingValueOptions: HELM_LEADING_VALUE_OPTIONS,
	});
	if ("error" in collected) {
		return unclassified(`helm uses an unsupported flag layout (${collected.error})`);
	}

	const topLevel = (collected.positionals[0] || "").toLowerCase();
	const nested = (collected.positionals[1] || "").toLowerCase();
	if (!topLevel) {
		if (invocation.args.some((arg) => arg === "-h" || arg === "--help")) return allow();
		return unclassified("helm command could not be classified safely");
	}

	if (topLevel === "get") {
		return knownRisk("helm get may expose stored release values or rendered secrets");
	}

	const nestedAllowlist = SAFE_HELM_NESTED[topLevel as keyof typeof SAFE_HELM_NESTED];
	if (nestedAllowlist) {
		if (nestedAllowlist.has(nested)) return allow();
		if (RISKY_HELM_NESTED[topLevel]?.has(nested)) {
			return knownRisk(`helm ${topLevel} ${nested} changes Helm or repository state`);
		}
		return unclassified(`helm ${topLevel} ${nested || "<unknown>"} is not on the low-risk allowlist`);
	}

	if (SAFE_HELM_TOP_LEVEL.has(topLevel)) return allow();
	if (RISKY_HELM_NESTED[topLevel]?.has(nested)) {
		return knownRisk(`helm ${topLevel} ${nested} changes Helm or registry state`);
	}
	if (RISKY_HELM_TOP_LEVEL.has(topLevel)) return knownRisk(`helm ${topLevel} changes release or registry state`);
	return unclassified(`helm ${topLevel} is not on the low-risk allowlist`);
}

function evaluateArgocd(invocation: Invocation): PolicyDecision {
	const collected = collectPositionals(invocation.args, {
		maxPositionals: 3,
		leadingBooleanOptions: ARGOCD_LEADING_BOOLEAN_OPTIONS,
		leadingValueOptions: ARGOCD_LEADING_VALUE_OPTIONS,
	});
	if ("error" in collected) {
		return unclassified(`argocd uses an unsupported flag layout (${collected.error})`);
	}

	const topLevel = (collected.positionals[0] || "").toLowerCase();
	const nested = (collected.positionals[1] || "").toLowerCase();
	const action = (collected.positionals[2] || "").toLowerCase();
	if (!topLevel) {
		if (invocation.args.some((arg) => arg === "-h" || arg === "--help" || arg === "--version")) return allow();
		return unclassified("argocd command could not be classified safely");
	}

	if (topLevel === "app" && (nested === "diff" || nested === "manifests")) {
		return knownRisk(`argocd app ${nested} may expose rendered secret material`);
	}
	if (topLevel === "app" && nested === "actions") {
		if (action === "list") return allow();
		if (action === "run") return knownRisk("argocd app actions run may execute a resource action");
		return unclassified(`argocd app actions ${action || "<unknown>"} is not on the low-risk allowlist`);
	}

	const nestedAllowlist = SAFE_ARGOCD_NESTED[topLevel as keyof typeof SAFE_ARGOCD_NESTED];
	if (nestedAllowlist) {
		if (nestedAllowlist.has(nested)) return allow();
		if (RISKY_ARGOCD_NESTED[topLevel]?.has(nested)) {
			return knownRisk(`argocd ${topLevel} ${nested} changes Argo CD state or credentials`);
		}
		return unclassified(`argocd ${topLevel} ${nested || "<unknown>"} is not on the low-risk allowlist`);
	}

	if (SAFE_ARGOCD_TOP_LEVEL.has(topLevel)) return allow();
	if (RISKY_ARGOCD_NESTED[topLevel]?.has(nested)) {
		return knownRisk(`argocd ${topLevel} ${nested} changes Argo CD state or credentials`);
	}
	if (RISKY_ARGOCD_TOP_LEVEL.has(topLevel)) return knownRisk(`argocd ${topLevel} changes authentication state`);
	return unclassified(`argocd ${topLevel} is not on the low-risk allowlist`);
}

export {
	allow,
	explicitRule,
	knownRisk,
	unclassified,
	isKubectlPortForwardOnlyCommand,
	evaluateKubectl,
	evaluateTerraform,
	evaluateHelm,
	evaluateArgocd,
	evaluateAws,
	evaluateAz,
	evaluateDocker,
	evaluateGit,
	evaluateVault,
	evaluateFind,
	evaluateGcloud,
	evaluateRsync,
	evaluateAlwaysDestructive,
	evaluateNonBypassableRisk,
	normalizeOverrideArguments,
	rsyncExecutableOptionValues,
};
export type { AllowDecision, ApprovalBasis, ApprovalDecision, PolicyDecision, ToolEvaluator };

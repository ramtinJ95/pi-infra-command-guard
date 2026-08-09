import {
	SHELL_CONTROL_KEYWORDS,
	SHELL_EXECUTION_BUILTINS,
	SHELL_RUNNERS,
	containsGuardedText,
	extractInvocation,
	parseSimpleCommands,
	recoverAstCommands,
	requiresAstRecovery,
	segmentsHaveDynamicExecutable,
	type Invocation,
} from "./shell.ts";
import {
	DEFAULT_COMMAND_POLICY_SETTINGS,
	GUARDED_EXECUTABLES,
	enabledGuardedExecutables,
	type CommandOverrides,
	type CommandPolicySettings,
	type GuardedExecutable,
} from "./guarded-executables.ts";
import {
	allow,
	explicitRule,
	evaluateArgocd,
	evaluateAws,
	evaluateAz,
	evaluateDocker,
	evaluateGit,
	evaluateVault,
	evaluateFind,
	evaluateGcloud,
	evaluateHelm,
	evaluateKubectl,
	evaluateRsync,
	evaluateTerraform,
	evaluateAlwaysDestructive,
	evaluateNonBypassableRisk,
	isKubectlPortForwardOnlyCommand,
	normalizeOverrideArguments,
	knownRisk,
	rsyncExecutableOptionValues,
	unclassified,
	type PolicyDecision,
	type ToolEvaluator,
} from "./tool-policies.ts";

const TOOL_EVALUATORS = {
	argocd: evaluateArgocd,
	aws: evaluateAws,
	az: evaluateAz,
	docker: evaluateDocker,
	git: evaluateGit,
	vault: evaluateVault,
	find: evaluateFind,
	gcloud: evaluateGcloud,
	helm: evaluateHelm,
	kubectl: evaluateKubectl,
	rm: () => knownRisk("rm command needs confirmation"),
	rmdir: (invocation) => evaluateAlwaysDestructive("rmdir", invocation),
	rsync: evaluateRsync,
	shred: (invocation) => evaluateAlwaysDestructive("shred", invocation),
	terraform: evaluateTerraform,
	truncate: (invocation) => evaluateAlwaysDestructive("truncate", invocation),
	unlink: (invocation) => evaluateAlwaysDestructive("unlink", invocation),
} satisfies Record<GuardedExecutable, ToolEvaluator>;

// Tool names added for narrow local-file actions are common search terms. Keep the
// conservative bare-text fallback for the original infrastructure tools, while
// still detecting every guarded executable in command position and shell runners.
const INDIRECT_TEXT_GUARDS = new Set<GuardedExecutable>([
	"argocd", "aws", "az", "docker", "gcloud", "helm", "kubectl", "rm", "terraform", "vault",
]);
const DEFAULT_ENABLED_INDIRECT_TEXT_GUARDS = GUARDED_EXECUTABLES.filter((executable) =>
	INDIRECT_TEXT_GUARDS.has(executable)
);
const FIND_RUNNER_CODE_FLAGS: Readonly<Record<string, readonly string[]>> = {
	bash: ["-c"],
	dash: ["-c"],
	fish: ["-c"],
	node: ["-e", "--eval", "-p", "--print"],
	perl: ["-e"],
	python: ["-c"],
	python3: ["-c"],
	"python3.11": ["-c"],
	"python3.12": ["-c"],
	ruby: ["-e"],
	sh: ["-c"],
	zsh: ["-c"],
};

function toolEvaluator(executable: string): ToolEvaluator | undefined {
	if (!Object.hasOwn(TOOL_EVALUATORS, executable)) return undefined;
	return TOOL_EVALUATORS[executable as GuardedExecutable];
}

function wildcardTokenMatches(pattern: string, value: string): boolean {
	const parts = pattern.split("*");
	if (parts.length === 1) return pattern === value;
	let cursor = 0;
	const first = parts[0];
	if (first) {
		if (!value.startsWith(first)) return false;
		cursor = first.length;
	}
	for (let index = 1; index < parts.length - 1; index += 1) {
		const part = parts[index];
		if (!part) continue;
		const matchIndex = value.indexOf(part, cursor);
		if (matchIndex === -1) return false;
		cursor = matchIndex + part.length;
	}
	const last = parts[parts.length - 1];
	return !last || (value.endsWith(last) && value.length - last.length >= cursor);
}

function commandRuleMatches(rule: string, args: string[]): boolean {
	const tokens = rule.split(" ");
	return tokens.length <= args.length && tokens.every((token, index) => wildcardTokenMatches(token, args[index]));
}

function matchingCommandOverride(
	executable: GuardedExecutable,
	invocation: Invocation,
	commandOverrides: CommandOverrides,
): { action: "allow" | "requireApproval"; rule: string } | undefined {
	const rules = commandOverrides[executable];
	if (rules.allow.length === 0 && rules.requireApproval.length === 0) return undefined;
	const args = normalizeOverrideArguments(executable, invocation.args);
	const requireApprovalRule = rules.requireApproval.find((rule) => commandRuleMatches(rule, args));
	if (requireApprovalRule) return { action: "requireApproval", rule: requireApprovalRule };
	const allowRule = rules.allow.find((rule) => commandRuleMatches(rule, args));
	return allowRule ? { action: "allow", rule: allowRule } : undefined;
}

function evaluateFindDelegatedCommands(
	invocation: Invocation,
	settings: CommandPolicySettings,
): PolicyDecision | undefined {
	const actions = new Set(["-exec", "-execdir", "-ok", "-okdir"]);
	let uncertainty: PolicyDecision | undefined;
	for (let index = 0; index < invocation.args.length; index += 1) {
		if (!actions.has(invocation.args[index])) continue;
		const end = invocation.args.findIndex((word, candidate) => candidate > index && (word === ";" || word === "+"));
		const nestedWords = invocation.args.slice(index + 1, end === -1 ? undefined : end);
		if (nestedWords.length === 0) continue;
		const nestedInvocation = extractInvocation(nestedWords);
		if (
			!("error" in nestedInvocation) &&
			(
				nestedInvocation.executable?.includes("{}") ||
				findRunnerCodeUsesPlaceholder(nestedInvocation)
			)
		) {
			uncertainty ??= unclassified("find delegates execution through a path placeholder, which requires manual approval");
			if (end !== -1) index = end;
			continue;
		}
		const nestedCommand = nestedWords.map((word) => JSON.stringify(word)).join(" ");
		const decision = classifyCommand(nestedCommand, settings);
		if (!decision.allow) {
			if (decision.basis !== "unclassified") return decision;
			uncertainty ??= decision;
		}
		if (end !== -1) index = end;
	}
	return uncertainty;
}

function findRunnerCodeUsesPlaceholder(invocation: Invocation): boolean {
	const codeFlags = FIND_RUNNER_CODE_FLAGS[invocation.executable ?? ""] ?? [];
	for (let index = 0; index < invocation.args.length; index += 1) {
		const argument = invocation.args[index];
		if (codeFlags.some((flag) => argument !== flag && argument.startsWith(flag))) {
			return argument.includes("{}");
		}
		if (codeFlags.includes(argument) && invocation.args[index + 1]?.includes("{}")) return true;
	}
	return false;
}

function classifyCommand(command: string, settings: CommandPolicySettings): PolicyDecision {
	const { guards: guardSettings, commands: commandOverrides } = settings;
	const enabledExecutables = settings === DEFAULT_COMMAND_POLICY_SETTINGS
		? GUARDED_EXECUTABLES
		: enabledGuardedExecutables(guardSettings);
	if (enabledExecutables.length === 0) return allow();

	const mentionsEnabledExecutable = containsGuardedText(command, enabledExecutables);
	const mayDelegateThroughDisabledFind = !guardSettings.find && /-(?:exec|execdir|ok|okdir)\b/.test(command) &&
		containsGuardedText(command, ["find"]);
	if (!mentionsEnabledExecutable && !mayDelegateThroughDisabledFind && !command.includes("$")) return allow();
	const kubectlOverrides = commandOverrides.kubectl;
	if (
		guardSettings.kubectl &&
		kubectlOverrides.allow.length === 0 &&
		kubectlOverrides.requireApproval.length === 0 &&
		isKubectlPortForwardOnlyCommand(command)
	) return allow();

	const parsed = parseSimpleCommands(command);
	const recovered = requiresAstRecovery(parsed) ? recoverAstCommands(command) : undefined;
	const segments = recovered?.segments ?? ("error" in parsed ? [] : parsed.segments);
	let uncertainty = recovered?.hasDynamicExecutable || segmentsHaveDynamicExecutable(segments)
		? unclassified("This command resolves its executable through a shell variable, which requires manual approval")
		: undefined;
	if (!mentionsEnabledExecutable && !mayDelegateThroughDisabledFind && !uncertainty) return allow();
	if (recovered) {
		const astDiagnostic = recovered.errors[0] ? `; Bash AST diagnostic: ${recovered.errors[0]}` : "";
		uncertainty ??= unclassified(
			"error" in parsed
				? `This command uses shell syntax outside the infra guard's provenance parser (${parsed.error}${astDiagnostic})`
				: `This command uses shell control flow outside the infra guard's provenance parser${astDiagnostic}`,
		);
		if (recovered.hasDynamicExecutable) {
			uncertainty = unclassified("This command resolves its executable through a shell expansion, which requires manual approval");
		}
	}
	const enabledIndirectTextGuards = enabledExecutables === GUARDED_EXECUTABLES
		? DEFAULT_ENABLED_INDIRECT_TEXT_GUARDS
		: enabledExecutables.filter((executable) => INDIRECT_TEXT_GUARDS.has(executable));

	for (const segment of segments) {
		if (segment.shadowedExecutable) {
			uncertainty ??= unclassified(
				`This command resolves ${segment.shadowedExecutable} to a shell function, which requires manual approval`,
			);
			continue;
		}
		const invocation = extractInvocation(segment.words);
		if ("error" in invocation) {
			uncertainty ??= unclassified(`This command uses a wrapper the infra guard cannot classify safely (${invocation.error})`);
			continue;
		}

		if (!invocation.executable) {
			if (containsGuardedText(segment.words.join(" "), enabledExecutables)) {
				uncertainty ??= unclassified("This command assigns guarded tooling for indirect shell execution, which requires manual approval");
			}
			continue;
		}

		if (SHELL_CONTROL_KEYWORDS.has(invocation.executable)) {
			uncertainty ??= unclassified(`This command uses shell control flow (${invocation.executable}), which requires manual approval`);
			continue;
		}

		if (SHELL_EXECUTION_BUILTINS.has(invocation.executable)) {
			uncertainty ??= unclassified(`This command uses shell execution syntax (${invocation.executable}), which requires manual approval`);
			continue;
		}

		const segmentText = segment.words.join(" ");
		const segmentMentionsGuardedTool = containsGuardedText(segmentText, enabledExecutables);
		if (SHELL_RUNNERS.has(invocation.executable) && segmentMentionsGuardedTool) {
			uncertainty ??= unclassified(`This command delegates guarded execution through ${invocation.executable}, which requires manual approval`);
			continue;
		}
		if (invocation.executable === "find") {
			const delegatedDecision = evaluateFindDelegatedCommands(invocation, settings);
			if (delegatedDecision && !delegatedDecision.allow) {
				if (delegatedDecision.basis !== "unclassified") return delegatedDecision;
				uncertainty ??= delegatedDecision;
			}
		}
		if (invocation.executable === "rsync") {
			const delegatedGuards = enabledExecutables.filter((executable) => executable !== "rsync");
			if (rsyncExecutableOptionValues(invocation.args).some((value) => containsGuardedText(value, delegatedGuards))) {
				return knownRisk("rsync executable option delegates to guarded tooling, which requires manual approval");
			}
		}

		const evaluator = toolEvaluator(invocation.executable);
		if (evaluator) {
			const executable = invocation.executable as GuardedExecutable;
			if (guardSettings[executable]) {
				const override = matchingCommandOverride(executable, invocation, commandOverrides);
				if (override?.action === "requireApproval") {
					return explicitRule(`Custom command rule requires approval for ${executable} ${override.rule}`);
				}
				if (override?.action === "allow") {
					const nonBypassableRisk = evaluateNonBypassableRisk(executable, invocation);
					if (nonBypassableRisk) {
						if (nonBypassableRisk.basis !== "unclassified") return nonBypassableRisk;
						uncertainty ??= nonBypassableRisk;
					}
					continue;
				}
				const decision = evaluator(invocation);
				if (!decision.allow) {
					if (decision.basis !== "unclassified") return decision;
					uncertainty ??= decision;
				}
			}
			continue;
		}

		if (containsGuardedText(segment.bare, enabledIndirectTextGuards)) {
			uncertainty ??= unclassified(
				`This command invokes guarded tooling through ${invocation.executable}, which requires manual approval`,
			);
		}
	}

	return uncertainty ?? allow();
}

function evaluateCommand(
	command: string,
	settings: CommandPolicySettings = DEFAULT_COMMAND_POLICY_SETTINGS,
): PolicyDecision {
	const decision = classifyCommand(command, settings);
	if (!decision.allow && decision.basis === "unclassified" && !settings.guardUnclassifiedCommands) return allow();
	return decision;
}

export {
	parseSimpleCommands,
	extractInvocation,
	collectPositionals,
	hasDynamicExecutable,
	isInteractiveInterpreterCommand,
} from "./shell.ts";
export {
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
	evaluateGcloud,
	evaluateFind,
	evaluateRsync,
} from "./tool-policies.ts";
export { evaluateCommand };
export type { PolicyDecision } from "./tool-policies.ts";

import {
	SHELL_CONTROL_KEYWORDS,
	SHELL_EXECUTION_BUILTINS,
	SHELL_RUNNERS,
	containsGuardedText,
	extractInvocation,
	hasDynamicExecutable,
	parseSimpleCommands,
	type Invocation,
} from "./shell.ts";
import {
	DEFAULT_COMMAND_OVERRIDES,
	DEFAULT_GUARD_SETTINGS,
	GUARDED_EXECUTABLES,
	enabledGuardedExecutables,
	type CommandOverrides,
	type GuardedExecutable,
	type GuardSettings,
} from "./guarded-executables.ts";
import {
	allow,
	evaluateArgocd,
	evaluateAws,
	evaluateAz,
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
	requireApproval,
	rsyncExecutableOptionValues,
	type PolicyDecision,
	type ToolEvaluator,
} from "./tool-policies.ts";

const TOOL_EVALUATORS = {
	argocd: evaluateArgocd,
	aws: evaluateAws,
	az: evaluateAz,
	find: evaluateFind,
	gcloud: evaluateGcloud,
	helm: evaluateHelm,
	kubectl: evaluateKubectl,
	rm: () => requireApproval("rm command needs confirmation"),
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
	"argocd", "aws", "az", "gcloud", "helm", "kubectl", "rm", "terraform",
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
	guardSettings: GuardSettings,
	commandOverrides: CommandOverrides,
): PolicyDecision | undefined {
	const actions = new Set(["-exec", "-execdir", "-ok", "-okdir"]);
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
			return requireApproval("find delegates execution through a path placeholder, which requires manual approval");
		}
		const nestedCommand = nestedWords.map((word) => JSON.stringify(word)).join(" ");
		const decision = evaluateCommand(nestedCommand, guardSettings, commandOverrides);
		if (!decision.allow) return decision;
		if (end !== -1) index = end;
	}
	return undefined;
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

function evaluateCommand(
	command: string,
	guardSettings: GuardSettings = DEFAULT_GUARD_SETTINGS,
	commandOverrides: CommandOverrides = DEFAULT_COMMAND_OVERRIDES,
): PolicyDecision {
	const enabledExecutables = guardSettings === DEFAULT_GUARD_SETTINGS
		? GUARDED_EXECUTABLES
		: enabledGuardedExecutables(guardSettings);
	if (enabledExecutables.length === 0) return allow();

	if (hasDynamicExecutable(command)) {
		return requireApproval("This command resolves its executable through a shell variable, which requires manual approval");
	}
	const mentionsEnabledExecutable = containsGuardedText(command, enabledExecutables);
	const mayDelegateThroughDisabledFind = !guardSettings.find && /-(?:exec|execdir|ok|okdir)\b/.test(command) &&
		containsGuardedText(command, ["find"]);
	if (!mentionsEnabledExecutable && !mayDelegateThroughDisabledFind) return allow();
	const kubectlOverrides = commandOverrides.kubectl;
	if (
		guardSettings.kubectl &&
		kubectlOverrides.allow.length === 0 &&
		kubectlOverrides.requireApproval.length === 0 &&
		isKubectlPortForwardOnlyCommand(command)
	) return allow();

	const parsed = parseSimpleCommands(command);
	if ("error" in parsed) {
		return requireApproval(`This command uses shell syntax the infra guard cannot classify safely (${parsed.error})`);
	}
	const enabledIndirectTextGuards = enabledExecutables === GUARDED_EXECUTABLES
		? DEFAULT_ENABLED_INDIRECT_TEXT_GUARDS
		: enabledExecutables.filter((executable) => INDIRECT_TEXT_GUARDS.has(executable));

	for (const segment of parsed.segments) {
		const invocation = extractInvocation(segment.words);
		if ("error" in invocation) {
			return requireApproval(`This command uses a wrapper the infra guard cannot classify safely (${invocation.error})`);
		}

		if (!invocation.executable) {
			if (containsGuardedText(segment.words.join(" "), enabledExecutables)) {
				return requireApproval("This command assigns guarded tooling for indirect shell execution, which requires manual approval");
			}
			continue;
		}

		if (SHELL_CONTROL_KEYWORDS.has(invocation.executable)) {
			return requireApproval(`This command uses shell control flow (${invocation.executable}), which requires manual approval`);
		}

		if (SHELL_EXECUTION_BUILTINS.has(invocation.executable)) {
			return requireApproval(`This command uses shell execution syntax (${invocation.executable}), which requires manual approval`);
		}

		const segmentText = segment.words.join(" ");
		const segmentMentionsGuardedTool = containsGuardedText(segmentText, enabledExecutables);
		if (SHELL_RUNNERS.has(invocation.executable) && segmentMentionsGuardedTool) {
			return requireApproval(`This command delegates guarded execution through ${invocation.executable}, which requires manual approval`);
		}
		if (invocation.executable === "find") {
			const delegatedDecision = evaluateFindDelegatedCommands(invocation, guardSettings, commandOverrides);
			if (delegatedDecision) return delegatedDecision;
		}
		if (invocation.executable === "rsync") {
			const delegatedGuards = enabledExecutables.filter((executable) => executable !== "rsync");
			if (rsyncExecutableOptionValues(invocation.args).some((value) => containsGuardedText(value, delegatedGuards))) {
				return requireApproval("rsync executable option delegates to guarded tooling, which requires manual approval");
			}
		}

		const evaluator = toolEvaluator(invocation.executable);
		if (evaluator) {
			const executable = invocation.executable as GuardedExecutable;
			if (guardSettings[executable]) {
				const override = commandOverrides === DEFAULT_COMMAND_OVERRIDES
					? undefined
					: matchingCommandOverride(executable, invocation, commandOverrides);
				if (override?.action === "requireApproval") {
					return requireApproval(`Custom command rule requires approval for ${executable} ${override.rule}`);
				}
				if (override?.action === "allow") {
					const nonBypassableRisk = evaluateNonBypassableRisk(executable, invocation);
					if (nonBypassableRisk) return nonBypassableRisk;
					continue;
				}
				const decision = evaluator(invocation);
				if (!decision.allow) return decision;
			}
			continue;
		}

		if (containsGuardedText(segment.bare, enabledIndirectTextGuards)) {
			return requireApproval(
				`This command invokes guarded tooling through ${invocation.executable}, which requires manual approval`,
			);
		}
	}

	return allow();
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
	evaluateGcloud,
	evaluateFind,
	evaluateRsync,
} from "./tool-policies.ts";
export { evaluateCommand };
export type { PolicyDecision } from "./tool-policies.ts";

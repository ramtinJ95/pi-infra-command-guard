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
	evaluateGcloud,
	evaluateHelm,
	evaluateKubectl,
	evaluateTerraform,
	evaluateNonBypassableRisk,
	isKubectlPortForwardOnlyCommand,
	normalizeOverrideArguments,
	requireApproval,
	type PolicyDecision,
	type ToolEvaluator,
} from "./tool-policies.ts";

const TOOL_EVALUATORS = {
	argocd: evaluateArgocd,
	aws: evaluateAws,
	az: evaluateAz,
	gcloud: evaluateGcloud,
	helm: evaluateHelm,
	kubectl: evaluateKubectl,
	rm: () => requireApproval("rm command needs confirmation"),
	terraform: evaluateTerraform,
} satisfies Record<GuardedExecutable, ToolEvaluator>;

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
	if (!containsGuardedText(command, enabledExecutables)) return allow();
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

		if (containsGuardedText(segment.bare, enabledExecutables)) {
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
} from "./tool-policies.ts";
export { evaluateCommand };
export type { PolicyDecision } from "./tool-policies.ts";

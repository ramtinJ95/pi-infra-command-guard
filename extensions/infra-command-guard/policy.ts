import {
	SHELL_CONTROL_KEYWORDS,
	SHELL_EXECUTION_BUILTINS,
	SHELL_RUNNERS,
	containsGuardedText,
	extractInvocation,
	hasDynamicExecutable,
	parseSimpleCommands,
} from "./shell.ts";
import { type GuardedExecutable } from "./guarded-executables.ts";
import {
	allow,
	evaluateArgocd,
	evaluateHelm,
	evaluateKubectl,
	evaluateTerraform,
	isKubectlPortForwardOnlyCommand,
	requireApproval,
	type PolicyDecision,
	type ToolEvaluator,
} from "./tool-policies.ts";

const TOOL_EVALUATORS = {
	argocd: evaluateArgocd,
	helm: evaluateHelm,
	kubectl: evaluateKubectl,
	rm: () => requireApproval("rm command needs confirmation"),
	terraform: evaluateTerraform,
} satisfies Record<GuardedExecutable, ToolEvaluator>;

function toolEvaluator(executable: string): ToolEvaluator | undefined {
	if (!Object.hasOwn(TOOL_EVALUATORS, executable)) return undefined;
	return TOOL_EVALUATORS[executable as GuardedExecutable];
}

function evaluateCommand(command: string): PolicyDecision {
	if (hasDynamicExecutable(command)) {
		return requireApproval("This command resolves its executable through a shell variable, which requires manual approval");
	}
	if (!containsGuardedText(command)) return allow();
	if (isKubectlPortForwardOnlyCommand(command)) return allow();

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
			if (containsGuardedText(segment.words.join(" "))) {
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
		const segmentMentionsGuardedTool = containsGuardedText(segmentText);
		if (SHELL_RUNNERS.has(invocation.executable) && segmentMentionsGuardedTool) {
			return requireApproval(`This command delegates guarded execution through ${invocation.executable}, which requires manual approval`);
		}

		const evaluator = toolEvaluator(invocation.executable);
		if (evaluator) {
			const decision = evaluator(invocation);
			if (!decision.allow) return decision;
			continue;
		}

		if (containsGuardedText(segment.bare)) {
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
} from "./tool-policies.ts";
export { evaluateCommand };
export type { PolicyDecision } from "./tool-policies.ts";

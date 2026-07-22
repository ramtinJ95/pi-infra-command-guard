import {
	SHELL_CONTROL_KEYWORDS,
	SHELL_EXECUTION_BUILTINS,
	SHELL_RUNNERS,
	containsGuardedText,
	containsRmText,
	extractInvocation,
	hasDynamicExecutable,
	parseSimpleCommands,
} from "./shell.ts";
import {
	allow,
	evaluateArgocd,
	evaluateHelm,
	evaluateKubectl,
	evaluateTerraform,
	isKubectlPortForwardOnlyCommand,
	requireApproval,
} from "./tool-policies.ts";

function evaluateCommand(command) {
	if (hasDynamicExecutable(command)) {
		return requireApproval("This command resolves its executable through a shell variable, which requires manual approval");
	}
	if (!containsGuardedText(command)) return allow();
	if (isKubectlPortForwardOnlyCommand(command)) return allow();

	const parsed = parseSimpleCommands(command);
	if (parsed.error) {
		return requireApproval(`This command uses shell syntax the infra guard cannot classify safely (${parsed.error})`);
	}

	for (const segment of parsed.segments) {
		const invocation = extractInvocation(segment.words);
		if (invocation.error) {
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

		if (invocation.executable === "rm") {
			return requireApproval("rm command needs confirmation");
		}

		if (invocation.executable === "kubectl") {
			const decision = evaluateKubectl(invocation);
			if (!decision.allow) return decision;
			continue;
		}

		if (invocation.executable === "terraform") {
			const decision = evaluateTerraform(invocation);
			if (!decision.allow) return decision;
			continue;
		}

		if (invocation.executable === "helm") {
			const decision = evaluateHelm(invocation);
			if (!decision.allow) return decision;
			continue;
		}

		if (invocation.executable === "argocd") {
			const decision = evaluateArgocd(invocation);
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

function checkRm(command) {
	if (!containsRmText(command)) return allow();
	const decision = evaluateCommand(command);
	return decision.allow ? allow() : decision;
}

function evaluateCommandWithRm(command) {
	return evaluateCommand(command);
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
export { evaluateCommand, checkRm, evaluateCommandWithRm };

const CODE_MODE_RUNTIME_KEY = Symbol.for("@howaboua/pi-codex-conversion.code-mode");
const CODE_MODE_GUARD_BRIDGE_KEY = Symbol.for("infra-command-guard.code-mode-bridge.v1");
const CODE_MODE_PROVIDER_WRAPPED = Symbol.for("infra-command-guard.code-mode-provider-wrapped.v1");
const CODE_MODE_TOOL_WRAPPED = Symbol.for("infra-command-guard.code-mode-tool-wrapped.v1");

type PropertyBag = Record<PropertyKey, unknown>;
type CodeModeGuardBridge = (input: unknown, context: unknown) => void | Promise<void>;
type CodeModeToolInvoke = (input: unknown, context: unknown, signal: AbortSignal) => unknown;

function isPropertyBag(value: unknown): value is PropertyBag {
	return typeof value === "object" && value !== null;
}

function codeModeRuntime(events: unknown): PropertyBag | undefined {
	if (!isPropertyBag(events)) return undefined;
	const state = events[CODE_MODE_RUNTIME_KEY];
	if (!isPropertyBag(state)) return undefined;
	return isPropertyBag(state.runtime) ? state.runtime : undefined;
}

function codeModeProviders(runtime: unknown): unknown[] | undefined {
	if (isPropertyBag(runtime) && runtime.providers instanceof Map) return [...runtime.providers.values()];
	return undefined;
}

function ensureCodeModeGuardInstalled(events: unknown, context: unknown): { ok: true } | { ok: false; reason: string } {
	const runtime = codeModeRuntime(events);
	if (!runtime) return { ok: false, reason: "Code Mode runtime was not found" };
	const providers = codeModeProviders(runtime);
	if (!providers) return { ok: false, reason: "Code Mode provider registry has an unsupported shape" };

	try {
		for (const candidate of providers) {
			if (!isPropertyBag(candidate) || typeof candidate.getTools !== "function" || candidate[CODE_MODE_PROVIDER_WRAPPED]) {
				continue;
			}
			const provider = candidate;
			const getTools = provider.getTools as (this: unknown, context: unknown) => unknown;
			provider.getTools = function guardedGetTools(this: unknown, providerContext: unknown) {
				const tools = getTools.call(this, providerContext);
				if (!Array.isArray(tools)) return tools;
				return tools.map((candidateTool: unknown) => {
					if (
						!isPropertyBag(candidateTool) ||
						candidateTool.name !== "exec_command" ||
						typeof candidateTool.invoke !== "function" ||
						candidateTool[CODE_MODE_TOOL_WRAPPED]
					) {
						return candidateTool;
					}
					const tool = candidateTool;
					const invoke = tool.invoke as CodeModeToolInvoke;
					const guardedTool = {
						...tool,
						async invoke(input: unknown, toolContext: unknown, signal: AbortSignal) {
							const bridge = isPropertyBag(events) ? events[CODE_MODE_GUARD_BRIDGE_KEY] : undefined;
							if (typeof bridge !== "function") {
								throw new Error("BLOCKED — infra-command-guard Code Mode bridge is unavailable. Reload Pi before using Code Mode.");
							}
							await bridge(input, toolContext);
							return invoke.call(tool, input, toolContext, signal);
						},
					};
					Object.defineProperty(guardedTool, CODE_MODE_TOOL_WRAPPED, { value: true });
					return guardedTool;
				});
			};
			Object.defineProperty(provider, CODE_MODE_PROVIDER_WRAPPED, { value: true });
		}

		const hasGuardedExec = providers.some((provider) => {
			if (!isPropertyBag(provider) || typeof provider.getTools !== "function") return false;
			const tools = provider.getTools(context);
			return Array.isArray(tools) && tools.some((tool: unknown) =>
				isPropertyBag(tool) && tool.name === "exec_command" && Boolean(tool[CODE_MODE_TOOL_WRAPPED]));
		});
		return hasGuardedExec
			? { ok: true }
			: { ok: false, reason: "Code Mode nested exec_command provider was not found" };
	} catch (error) {
		return {
			ok: false,
			reason: `Code Mode guard installation failed: ${error instanceof Error ? error.message : String(error)}`,
		};
	}
}

export {
	CODE_MODE_RUNTIME_KEY,
	CODE_MODE_GUARD_BRIDGE_KEY,
	CODE_MODE_PROVIDER_WRAPPED,
	CODE_MODE_TOOL_WRAPPED,
	codeModeRuntime,
	codeModeProviders,
	ensureCodeModeGuardInstalled,
};
export type { CodeModeGuardBridge };

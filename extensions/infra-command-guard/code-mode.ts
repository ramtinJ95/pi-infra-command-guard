const CODE_MODE_RUNTIME_KEY = Symbol.for("@howaboua/pi-codex-conversion.code-mode");
const CODE_MODE_GUARD_BRIDGE_KEY = Symbol.for("infra-command-guard.code-mode-bridge.v1");
const CODE_MODE_PROVIDER_WRAPPED = Symbol.for("infra-command-guard.code-mode-provider-wrapped.v1");
const CODE_MODE_TOOL_WRAPPED = Symbol.for("infra-command-guard.code-mode-tool-wrapped.v1");

type CodeModeGuardBridge = (input: unknown, context: any) => void | Promise<void>;

function codeModeRuntime(events: any): any | undefined {
	const state = events?.[CODE_MODE_RUNTIME_KEY];
	if (!state || typeof state !== "object") return undefined;
	return state.runtime && typeof state.runtime === "object" ? state.runtime : undefined;
}

function codeModeProviders(runtime: any): any[] | undefined {
	if (runtime?.providers instanceof Map) return [...runtime.providers.values()];
	return undefined;
}

function ensureCodeModeGuardInstalled(events: any, context: any): { ok: true } | { ok: false; reason: string } {
	const runtime = codeModeRuntime(events);
	if (!runtime) return { ok: false, reason: "Code Mode runtime was not found" };
	const providers = codeModeProviders(runtime);
	if (!providers) return { ok: false, reason: "Code Mode provider registry has an unsupported shape" };

	try {
		for (const provider of providers) {
			if (!provider || typeof provider.getTools !== "function" || provider[CODE_MODE_PROVIDER_WRAPPED]) continue;
			const getTools = provider.getTools;
			provider.getTools = function guardedGetTools(providerContext: any) {
				const tools = getTools.call(this, providerContext);
				if (!Array.isArray(tools)) return tools;
				return tools.map((tool) => {
					if (!tool || tool.name !== "exec_command" || typeof tool.invoke !== "function" || tool[CODE_MODE_TOOL_WRAPPED]) {
						return tool;
					}
					const invoke = tool.invoke;
					const guardedTool = {
						...tool,
						async invoke(input: unknown, toolContext: any, signal: AbortSignal) {
							const bridge = events?.[CODE_MODE_GUARD_BRIDGE_KEY];
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
			if (!provider || typeof provider.getTools !== "function") return false;
			const tools = provider.getTools(context);
			return Array.isArray(tools) && tools.some((tool) => tool?.name === "exec_command" && tool[CODE_MODE_TOOL_WRAPPED]);
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

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { createBashTool } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import {
	APPROVAL_STORE_KEY,
	ApprovalStore,
	executionFingerprint,
	executionIdentity,
	guardExecution,
} from "./approvals.ts";
import { requestInfraApproval } from "./approval-ui.ts";
import {
	autoNotificationBackend,
	customSoundProcesses,
	detectTerminalNotificationBackend,
	isHerdrPane,
	loadApprovalAttentionSettings,
	nativeNotificationProcesses,
	parseApprovalAttentionSettings,
	parseHerdrNotificationOutput,
	requestApprovalAttention,
	sendTerminalNotification,
	shouldUseNativeNotification,
	terminalNotificationSequence,
} from "./attention.ts";
import {
	CODE_MODE_GUARD_BRIDGE_KEY,
	CODE_MODE_PROVIDER_WRAPPED,
	CODE_MODE_RUNTIME_KEY,
	CODE_MODE_TOOL_WRAPPED,
	codeModeProviders,
	codeModeRuntime,
	ensureCodeModeGuardInstalled,
	type CodeModeGuardBridge,
} from "./code-mode.ts";
import {
	checkRm,
	collectPositionals,
	evaluateArgocd,
	evaluateCommand,
	evaluateCommandWithRm,
	evaluateHelm,
	evaluateKubectl,
	evaluateTerraform,
	extractInvocation,
	hasDynamicExecutable,
	isInteractiveInterpreterCommand,
	isKubectlPortForwardOnlyCommand,
	parseSimpleCommands,
} from "./policy.ts";

const CODE_MODE_PUBLIC_TOOL_NAMES = new Set(["exec", "wait", "functions.exec", "functions.wait"]);

const ApproveInfraCommandParams = Type.Object({
	request_id: Type.String({ description: "The approval request identifier from the blocked tool result." }),
	command: Type.String({ description: "The exact blocked command, byte-for-byte. Do not edit or normalize." }),
	reason: Type.String({ description: "The infra-command-guard block reason." }),
	summary: Type.String({ description: "Plain-language summary of what the command does. Do not repeat the command text." }),
	flags: Type.Array(
		Type.Object({
			flag: Type.String({ description: "The flag, option, or argument name, e.g. --dry-run=client." }),
			meaning: Type.String({ description: "What this flag or option changes about the command." }),
		}),
		{ description: "Important flags/options and their meanings. Use [] if none are important." },
	),
	blastRadius: Type.String({ description: "Concrete blast radius: what changes, what data is exposed, and worst-case impact." }),
});

export default function createExtension(pi: ExtensionAPI) {
	const bashTool = createBashTool(process.cwd());
	const approvals = new ApprovalStore();
	const events = pi.events as unknown as Record<PropertyKey, unknown>;
	events[APPROVAL_STORE_KEY] = approvals;
	const currentApprovals = (): ApprovalStore => events[APPROVAL_STORE_KEY] as ApprovalStore;
	const codeModeBridge: CodeModeGuardBridge = (input, context) => {
		const contextRecord = typeof context === "object" && context !== null
			? context as Record<string, unknown>
			: {};
		const nestedContext = typeof contextRecord.extensionContext === "object" && contextRecord.extensionContext !== null
			? contextRecord.extensionContext as Record<string, unknown>
			: contextRecord;
		const identity = executionIdentity(
			"code-mode-exec-command",
			input,
			typeof contextRecord.cwd === "string"
				? contextRecord.cwd
				: typeof nestedContext.cwd === "string"
					? nestedContext.cwd
					: process.cwd(),
		);
		if (!identity) {
			throw new Error("BLOCKED — infra-command-guard could not identify the nested exec_command request.");
		}
		const guarded = guardExecution(
			currentApprovals(),
			identity,
			typeof nestedContext.mode === "string" ? nestedContext.mode : undefined,
		);
		if (!guarded.allow) throw new Error(guarded.reason);
	};
	events[CODE_MODE_GUARD_BRIDGE_KEY] = codeModeBridge;
	const prepareCodeModeGuard = (ctx: ExtensionContext) => {
		if (!codeModeRuntime(events)) return undefined;
		return ensureCodeModeGuardInstalled(events, ctx);
	};

	pi.on("session_start", (_event, ctx) => {
		prepareCodeModeGuard(ctx);
	});
	pi.on("before_agent_start", (_event, ctx) => {
		prepareCodeModeGuard(ctx);
	});

	pi.registerCommand("infra-guard-notify-test", {
		description: "Test infra-command-guard notification and sound configuration",
		handler: async (_args, ctx) => {
			const route = await requestApprovalAttention(
				ctx,
				"Pi infrastructure guard",
				"Notification test from the active infra-command-guard configuration.",
			);
			await ctx.ui.confirm(
				"infra-command-guard notification test",
				`Dispatched via: ${route}\n\nDid the configured notification and sound behavior occur?`,
			);
		},
	});

	pi.registerTool({
		name: "approve_infra_command",
		label: "Approve Infra Command",
		description:
			"Ask the user to approve one exact blocked infra or rm command with structured risk details.",
		promptSnippet: "Ask the user to approve one exact blocked infra/rm command with structured risk details.",
		promptGuidelines: [
			"Use approve_infra_command only after infra-command-guard blocks a shell command and explicitly instructs you to use it.",
			"Pass the approval request identifier from that blocked shell result as request_id.",
			"When using approve_infra_command, pass the exact blocked command byte-for-byte; do not edit, normalize, quote, or simplify it.",
			"When using approve_infra_command, keep summary, flags, and blastRadius non-overlapping; the approval UI renders command and reason separately.",
		],
		parameters: ApproveInfraCommandParams,
		async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
			const approvalStore = currentApprovals();
			const validation = approvalStore.validate(params.request_id, params.command, params.reason);
			if (!validation.ok) {
				return {
					content: [{ type: "text", text: validation.error }],
					details: { approved: false, requestId: params.request_id, reason: params.reason, command: params.command },
				};
			}

			if (ctx.mode !== "tui") {
				return {
					content: [{ type: "text", text: "Cannot approve: TUI approval UI is not available. Do not retry the command." }],
					details: { approved: false, requestId: validation.pending.id, reason: params.reason, command: params.command },
				};
			}

			await requestApprovalAttention(ctx);
			const approved = await requestInfraApproval(
				ctx,
				{ summary: params.summary, flags: params.flags, blastRadius: params.blastRadius },
				params.reason,
				params.command,
			);
			if (!approved) {
				approvalStore.cancel(validation.pending.id);
				return {
					content: [{ type: "text", text: "User cancelled. Do not retry the command." }],
					details: { approved: false, requestId: validation.pending.id, reason: params.reason, command: params.command },
				};
			}

			const granted = approvalStore.approve(validation.pending.id, params.command, params.reason);
			if (!granted.ok) {
				return {
					content: [{ type: "text", text: granted.error }],
					details: { approved: false, requestId: params.request_id, reason: params.reason, command: params.command },
				};
			}
			return {
				content: [{ type: "text", text: "Approved once. Retry the exact same command with the same execution context now." }],
				details: { approved: true, requestId: validation.pending.id, reason: params.reason, command: params.command },
			};
		},
	});

	pi.on("tool_call", (event, ctx) => {
		if (CODE_MODE_PUBLIC_TOOL_NAMES.has(event.toolName)) {
			const installed = prepareCodeModeGuard(ctx) ?? {
				ok: false as const,
				reason: "Code Mode runtime was not found",
			};
			if (installed.ok) return undefined;
			return {
				block: true,
				reason: `BLOCKED — infra-command-guard cannot safely intercept Code Mode: ${installed.reason}. Reload Pi or disable Code Mode before running commands.`,
			};
		}

		if (event.toolName !== "exec_command" && event.toolName !== "functions.exec_command") return undefined;

		const identity = executionIdentity("exec-command", event.input, ctx.cwd);
		if (!identity) return undefined;
		const guarded = guardExecution(currentApprovals(), identity, ctx.mode);
		return guarded.allow ? undefined : { block: true, reason: guarded.reason };
	});

	pi.registerTool({
		...bashTool,
		execute: async (toolCallId, params, signal, onUpdate, ctx) => {
			const identity = executionIdentity("bash", params, process.cwd());
			if (!identity) return bashTool.execute(toolCallId, params, signal, onUpdate);
			const guarded = guardExecution(currentApprovals(), identity, ctx.mode);
			if (!guarded.allow) throw new Error(guarded.reason);
			return bashTool.execute(toolCallId, params, signal, onUpdate);
		},
	});

	pi.on("session_shutdown", () => {
		if (events[CODE_MODE_GUARD_BRIDGE_KEY] === codeModeBridge) {
			delete events[CODE_MODE_GUARD_BRIDGE_KEY];
		}
		if (events[APPROVAL_STORE_KEY] === approvals) delete events[APPROVAL_STORE_KEY];
	});
}

export const _test = {
	parseSimpleCommands,
	extractInvocation,
	collectPositionals,
	isKubectlPortForwardOnlyCommand,
	evaluateCommand,
	evaluateKubectl,
	evaluateTerraform,
	evaluateHelm,
	evaluateArgocd,
	checkRm,
	evaluateCommandWithRm,
	hasDynamicExecutable,
	parseApprovalAttentionSettings,
	loadApprovalAttentionSettings,
	detectTerminalNotificationBackend,
	autoNotificationBackend,
	isHerdrPane,
	shouldUseNativeNotification,
	parseHerdrNotificationOutput,
	terminalNotificationSequence,
	sendTerminalNotification,
	customSoundProcesses,
	nativeNotificationProcesses,
	isInteractiveInterpreterCommand,
	executionFingerprint,
	executionIdentity,
	ApprovalStore,
	guardExecution,
	ensureCodeModeGuardInstalled,
	codeModeProviders,
	CODE_MODE_RUNTIME_KEY,
	CODE_MODE_GUARD_BRIDGE_KEY,
	APPROVAL_STORE_KEY,
	CODE_MODE_PROVIDER_WRAPPED,
	CODE_MODE_TOOL_WRAPPED,
};

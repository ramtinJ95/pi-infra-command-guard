import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { createBashTool } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import {
	APPROVAL_STORE_KEY,
	ApprovalStore,
	executionIdentity,
	guardExecution,
} from "./approvals.ts";
import { requestInfraApproval } from "./approval-ui.ts";
import { loadPolicySettings, requestApprovalAttention } from "./attention.ts";
import {
	registerCodeModeToolPreflight,
	type CodeModeToolPreflight,
} from "./code-mode.ts";
import {
	hasEnabledGuards,
	type CommandPolicySettings,
} from "./guarded-executables.ts";

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
	let lastConfigWarning: string | undefined;
	let lastGuardRevision: string | undefined;
	const currentPolicySettings = (context?: { ui?: ExtensionContext["ui"] }): CommandPolicySettings => {
		const loaded = loadPolicySettings();
		const revision = `${loaded.error ? `invalid:${loaded.error}:` : "valid:"}${JSON.stringify(loaded.settings)}`;
		if (lastGuardRevision !== undefined && revision !== lastGuardRevision) {
			currentApprovals().clear();
		}
		lastGuardRevision = revision;
		if (!loaded.error) {
			lastConfigWarning = undefined;
			return loaded.settings;
		}
		const warning = `infra-command-guard could not read ${loaded.configPath}: ${loaded.error}. All command guards remain enabled with built-in policies.`;
		if (warning !== lastConfigWarning) {
			try {
				if (context?.ui?.notify) {
					context.ui.notify(warning, "warning");
					lastConfigWarning = warning;
				}
			} catch {}
		}
		return loaded.settings;
	};
	const codeModeGuard: CodeModeToolPreflight = (call) => {
		if (call.toolName !== "exec_command") return undefined;
		const nestedContext = call.extensionContext;
		const policySettings = currentPolicySettings(nestedContext);
		if (!hasEnabledGuards(policySettings.guards)) return undefined;
		const identity = executionIdentity(
			"code-mode-exec-command",
			call.input,
			call.cwd,
		);
		if (!identity) {
			return {
				block: true,
				reason: "BLOCKED — infra-command-guard could not identify the nested exec_command request.",
			};
		}
		const guarded = guardExecution(
			currentApprovals(),
			identity,
			nestedContext?.mode,
			policySettings,
		);
		return guarded.allow ? undefined : { block: true, reason: guarded.reason };
	};
	const codeModeRegistration = registerCodeModeToolPreflight(pi, codeModeGuard);

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
			currentPolicySettings(ctx);
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
			const policySettings = currentPolicySettings(ctx);
			if (!hasEnabledGuards(policySettings.guards)) return undefined;
			if (codeModeRegistration.isAvailable()) return undefined;
			return {
				block: true,
				reason: "BLOCKED — infra-command-guard cannot safely intercept Code Mode because its nested-tool preflight API is unavailable. Update pi-codex-conversion or disable Code Mode before running commands.",
			};
		}

		if (event.toolName !== "exec_command" && event.toolName !== "functions.exec_command") return undefined;

		const identity = executionIdentity("exec-command", event.input, ctx.cwd);
		if (!identity) return undefined;
		const policySettings = currentPolicySettings(ctx);
		const guarded = guardExecution(
			currentApprovals(),
			identity,
			ctx.mode,
			policySettings,
		);
		return guarded.allow ? undefined : { block: true, reason: guarded.reason };
	});

	pi.registerTool({
		...bashTool,
		execute: async (toolCallId, params, signal, onUpdate, ctx) => {
			const identity = executionIdentity("bash", params, process.cwd());
			if (!identity) return bashTool.execute(toolCallId, params, signal, onUpdate);
			const policySettings = currentPolicySettings(ctx);
			const guarded = guardExecution(
				currentApprovals(),
				identity,
				ctx.mode,
				policySettings,
			);
			if (!guarded.allow) throw new Error(guarded.reason);
			return bashTool.execute(toolCallId, params, signal, onUpdate);
		},
	});

	pi.on("session_shutdown", () => {
		if (events[APPROVAL_STORE_KEY] === approvals) delete events[APPROVAL_STORE_KEY];
	});
}

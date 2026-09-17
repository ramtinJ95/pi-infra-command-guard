import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { createBashTool } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import {
	APPROVAL_STORE_KEY,
	BYPASS_STORE_KEY,
	ApprovalStore,
	executionIdentity,
	guardExecution,
	type GuardDecision,
	type PendingApproval,
} from "./approvals.ts";
import {
	DURATION_OPTIONS,
	GuardBypassStore,
	describeBypassScope,
	findMatchingBypassRule,
	formatDuration,
	parseDurationArgument,
	sameBypassScope,
} from "./bypass.ts";
import { requestInfraApproval } from "./approval-ui.ts";
import { loadGuardConfiguration, requestApprovalAttention } from "./attention.ts";
import {
	DEFAULT_TYPESAFE_SETTINGS,
	TYPESAFE_API_KEY_ENV,
	TYPESAFE_STORE_KEY,
	TypeSafeReviewStore,
	hasTypeSafeCredentials,
	persistTypeSafeEnabled,
	reviewAdvisory,
	skippedReviewAdvisory,
	type AdvisoryNote,
	type ReviewTransport,
	type TypeSafeSettings,
} from "./typesafe.ts";
import {
	registerCodeModeToolPreflight,
	type CodeModeToolPreflight,
} from "./code-mode.ts";
import {
	hasEnabledGuards,
	type CommandPolicySettings,
	type GuardedExecutable,
} from "./guarded-executables.ts";

const CODE_MODE_PUBLIC_TOOL_NAMES = new Set(["exec", "wait", "functions.exec", "functions.wait"]);
const BYPASS_OFFER_FLAG = { flag: "Scoped bypass option", meaning: "bypass flag" };
const TYPESAFE_COMMAND = "infra-guard-typesafe";
const TYPESAFE_COMMAND_ACTIONS = ["status", "enable", "pause", "resume", "disable"] as const;
const TYPESAFE_USAGE = `Usage: /${TYPESAFE_COMMAND} [${TYPESAFE_COMMAND_ACTIONS.join("|")}] — pause accepts ${DURATION_OPTIONS.map((option) => option.label).join(", ")}`;

type ExtensionDependencies = {
	// Injected by tests; production uses the global fetch and Pi's environment.
	typeSafeTransport?: ReviewTransport;
};

// Resolves with the promise's value, or with undefined as soon as `signal`
// aborts. The underlying promise is left to settle on its own.
function untilAborted<T>(promise: Promise<T>, signal: AbortSignal | undefined): Promise<T | undefined> {
	if (!signal) return promise;
	if (signal.aborted) return Promise.resolve(undefined);
	return new Promise<T | undefined>((resolve, reject) => {
		const onAbort = () => resolve(undefined);
		signal.addEventListener("abort", onAbort, { once: true });
		promise.then(
			(value) => {
				signal.removeEventListener("abort", onAbort);
				resolve(value);
			},
			(error: unknown) => {
				signal.removeEventListener("abort", onAbort);
				reject(error);
			},
		);
	});
}

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

export default function createExtension(pi: ExtensionAPI, dependencies: ExtensionDependencies = {}) {
	const bashTool = createBashTool(process.cwd());
	const approvals = new ApprovalStore();
	const bypasses = new GuardBypassStore();
	const typeSafeReviews = new TypeSafeReviewStore();
	const typeSafeTransport: ReviewTransport = dependencies.typeSafeTransport ?? {
		fetch: (input, init) => globalThis.fetch(input, init),
		env: process.env,
	};
	const events = pi.events as unknown as Record<PropertyKey, unknown>;
	events[APPROVAL_STORE_KEY] = approvals;
	events[BYPASS_STORE_KEY] = bypasses;
	events[TYPESAFE_STORE_KEY] = typeSafeReviews;
	const currentApprovals = (): ApprovalStore => events[APPROVAL_STORE_KEY] as ApprovalStore;
	const currentBypasses = (): GuardBypassStore => events[BYPASS_STORE_KEY] as GuardBypassStore;
	const currentTypeSafe = (): TypeSafeReviewStore => events[TYPESAFE_STORE_KEY] as TypeSafeReviewStore;
	let lastBypassState: string[] = [];
	const syncBypassStatus = (context?: { ui?: ExtensionContext["ui"] }): void => {
		const lines = [...currentBypasses().describe(), ...currentTypeSafe().describe()];
		const changed =
			lines.length !== lastBypassState.length ||
			lines.some((line, index) => line !== lastBypassState[index]);
		if (!changed) return;
		lastBypassState = [...lines];
		try {
			context?.ui?.setStatus("infra-command-guard", lines.length > 0 ? lines.join(" | ") : undefined);
		} catch {}
	};
	let lastConfigWarning: string | undefined;
	let lastGuardRevision: string | undefined;
	let lastTypeSafeRevision: string | undefined;
	// The TypeSafe toggle is read from the same file in the same pass as the
	// policy settings, so no extra file read is added to the per-command path.
	// Configuration is not watched: a direct JSON edit is observed the next time
	// this runs (the next shell command, approval request, or slash command).
	let currentTypeSafeSettings: TypeSafeSettings = DEFAULT_TYPESAFE_SETTINGS;
	let currentConfigState: { configPath: string; error?: string | undefined } = { configPath: "" };
	const currentPolicySettings = (context?: { ui?: ExtensionContext["ui"] }): CommandPolicySettings => {
		const loaded = loadGuardConfiguration();
		currentTypeSafeSettings = loaded.typesafe;
		currentConfigState = { configPath: loaded.configPath, error: loaded.error };
		const revision = `${loaded.error ? `invalid:${loaded.error}:` : "valid:"}${JSON.stringify(loaded.policy)}`;
		if (lastGuardRevision !== undefined && revision !== lastGuardRevision) {
			currentApprovals().clear();
		}
		lastGuardRevision = revision;
		// Any observed change to the TypeSafe settings (including the file becoming
		// invalid) aborts in-flight reviews and forgets cached ones, so a review
		// started under the previous settings is never shown or reused later. A
		// disabling change also ends the session pause, as `disable` does.
		const typeSafeRevision = `${loaded.error ? "invalid" : "valid"}:${JSON.stringify(loaded.typesafe)}`;
		if (lastTypeSafeRevision !== undefined && typeSafeRevision !== lastTypeSafeRevision) {
			const store = currentTypeSafe();
			store.clear();
			if (!loaded.typesafe.enabled) store.pause.resume();
			syncBypassStatus(context);
		}
		lastTypeSafeRevision = typeSafeRevision;
		if (!loaded.error) {
			lastConfigWarning = undefined;
			return loaded.policy;
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
		return loaded.policy;
	};
	const typeSafeActive = (): boolean => currentTypeSafeSettings.enabled && !currentTypeSafe().pause.isPaused();
	let lastTypeSafeWarning: string | undefined;
	const warnTypeSafe = (context: { ui?: ExtensionContext["ui"] } | undefined, warning: string): void => {
		if (warning === lastTypeSafeWarning) return;
		try {
			if (context?.ui?.notify) {
				context.ui.notify(warning, "warning");
				lastTypeSafeWarning = warning;
			}
		} catch {}
	};
	// Starts the advisory review for a fresh TUI block whose basis is a positively
	// recognized risk. Allowed commands, unclassified blocks, custom-rule blocks,
	// non-TUI blocks, and retries of approved commands never reach this point.
	const beginTypeSafeReview = (
		guarded: GuardDecision,
		command: string,
		context: { ui?: ExtensionContext["ui"] } | undefined,
	): void => {
		if (guarded.allow || !guarded.requestId || guarded.basis !== "knownRisk" || guarded.policyReason === undefined) return;
		if (!typeSafeActive()) return;
		if (!hasTypeSafeCredentials(typeSafeTransport.env)) {
			warnTypeSafe(
				context,
				`infra-command-guard TypeSafe review is enabled but ${TYPESAFE_API_KEY_ENV} is not set; blocks still require normal approval. Set the variable and restart Pi, or run /${TYPESAFE_COMMAND} disable.`,
			);
		}
		currentTypeSafe().begin(command, guarded.policyReason, currentTypeSafeSettings, typeSafeTransport);
	};
	// Resolves the advisory for the approval overlay. Returns nothing when the
	// review is disabled or paused now, including a pause or configuration change
	// that happened while the review was in flight. Stops waiting as soon as the
	// approval tool call is aborted; the review itself stays cached for a retry.
	const typeSafeAdvisory = async (
		pending: PendingApproval,
		context: { ui?: ExtensionContext["ui"] } | undefined,
		signal: AbortSignal | undefined,
	): Promise<AdvisoryNote | undefined> => {
		if (!typeSafeActive()) return undefined;
		if (pending.basis !== "knownRisk") return skippedReviewAdvisory("not-known-risk");
		const record = currentTypeSafe().lookup(pending.identity.command, pending.reason);
		if (!record) return skippedReviewAdvisory("not-requested");
		const outcome = await untilAborted(record.outcome, signal);
		if (outcome === undefined) return undefined;
		// Re-read the file: it may have been disabled while we waited.
		currentPolicySettings(context);
		if (!typeSafeActive()) return undefined;
		if (outcome.status === "failed" || outcome.status === "timed-out" || outcome.status === "not-sent") {
			warnTypeSafe(
				context,
				`infra-command-guard TypeSafe review ${
					outcome.status === "failed"
						? `failed: ${outcome.detail}`
						: outcome.status === "not-sent"
							? `was not sent: ${outcome.detail}`
							: `timed out after ${outcome.timeoutMs} ms`
				}. The normal approval flow is unaffected.`,
			);
		}
		return reviewAdvisory(record, outcome);
	};
	const describeTypeSafeState = (): string => {
		if (currentConfigState.error) return `TypeSafe review: unavailable (configuration invalid: ${currentConfigState.error})`;
		if (!currentTypeSafeSettings.enabled) return "TypeSafe review: disabled (integrations.typesafe.enabled is false or omitted)";
		const remaining = currentTypeSafe().pause.remainingMs();
		const credentials = hasTypeSafeCredentials(typeSafeTransport.env) ? "" : ` — ${TYPESAFE_API_KEY_ENV} is not set`;
		return remaining === undefined
			? `TypeSafe review: enabled (advisory only, ${currentTypeSafeSettings.timeoutMs} ms timeout)${credentials}`
			: `TypeSafe review: enabled, paused for ${formatDuration(remaining)}${credentials}`;
	};
	const codeModeGuard: CodeModeToolPreflight = (call) => {
		if (call.toolName !== "exec_command") return undefined;
		const nestedContext = call.extensionContext;
		const policySettings = currentPolicySettings(nestedContext);
		if (!hasEnabledGuards(policySettings.guards)) return undefined;
		syncBypassStatus(nestedContext);
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
			currentBypasses(),
		);
		beginTypeSafeReview(guarded, identity.command, nestedContext);
		return guarded.allow ? undefined : { block: true, reason: guarded.reason };
	};
	const codeModeRegistration = registerCodeModeToolPreflight(pi, codeModeGuard);

	pi.registerCommand("infra-guard", {
		description: "Manage infra-command-guard pauses and scoped bypasses",
		handler: async (_args, ctx) => {
			if (!ctx.hasUI || ctx.mode !== "tui") {
				const lines = currentBypasses().describe();
				ctx.ui.notify(
					lines.length > 0 ? `infra-command-guard — ${lines.join(" | ")}` : "infra-command-guard — no active pauses or bypasses",
					"info",
				);
				return;
			}
			const bypassStore = currentBypasses();
			const paused = bypassStore.isPaused();
			const activeRules = bypassStore.listRules();
			const removeOptions = activeRules.map((rule, index) => ({
				label: `Remove bypass ${index + 1}: ${bypassStore.describeRule(rule)}`,
				rule,
			}));
			const pauseOption = paused ? "Resume guard now" : "Pause guard…";
			const clearOption = "Clear all pauses and bypasses";
			const activeCount = (paused ? 1 : 0) + activeRules.length;
			const options = [
				pauseOption,
				...removeOptions.map((option) => option.label),
				...(activeCount > 1 ? [clearOption] : []),
			];
			const choice = await ctx.ui.select("infra-command-guard", options);
			if (!choice) return;
			if (choice === pauseOption) {
				if (paused) {
					bypassStore.resume();
					currentApprovals().clear();
					syncBypassStatus(ctx);
					ctx.ui.notify("infra-command-guard resumed.", "info");
					return;
				}
				const duration = await ctx.ui.select(
					"Pause infra-command-guard for…",
					DURATION_OPTIONS.map((option) => option.label),
				);
				const option = DURATION_OPTIONS.find((candidate) => candidate.label === duration);
				if (!option) return;
				bypassStore.pause(option.value);
				currentApprovals().clear();
				syncBypassStatus(ctx);
				ctx.ui.notify(`infra-command-guard paused for ${option.label}.`, "warning");
				return;
			}
			const removal = removeOptions.find((option) => option.label === choice);
			if (removal) {
				const { rule } = removal;
				if (!bypassStore.removeRule(rule)) return;
				currentApprovals().clear();
				syncBypassStatus(ctx);
				ctx.ui.notify(`Removed bypass: ${describeBypassScope(rule.executable, rule.scope)} in ${rule.cwd}`, "info");
				return;
			}
			if (choice === clearOption) {
				bypassStore.clear();
				currentApprovals().clear();
				syncBypassStatus(ctx);
				ctx.ui.notify("All infra-command-guard pauses and bypasses cleared.", "info");
			}
		},
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

	pi.registerCommand(TYPESAFE_COMMAND, {
		description: "Manage the experimental TypeSafe review of known-risk blocks: status, enable, pause, resume, disable",
		getArgumentCompletions: (prefix) => {
			const items = TYPESAFE_COMMAND_ACTIONS.filter((action) => action.startsWith(prefix.trim().toLowerCase()))
				.map((action) => ({ value: action, label: action }));
			return items.length > 0 ? items : null;
		},
		handler: async (args, ctx) => {
			currentPolicySettings(ctx);
			const store = currentTypeSafe();
			const [rawAction = "", ...rest] = args.trim().split(/\s+/).filter(Boolean);
			const action = rawAction.toLowerCase();
			const interactive = ctx.hasUI && ctx.mode === "tui";
			const persist = (enabled: boolean): boolean => {
				if (currentConfigState.error) {
					ctx.ui.notify(
						`infra-command-guard cannot change TypeSafe settings while ${currentConfigState.configPath} is invalid: ${currentConfigState.error}`,
						"error",
					);
					return false;
				}
				const written = persistTypeSafeEnabled(currentConfigState.configPath, enabled);
				if (!written.ok) {
					ctx.ui.notify(`infra-command-guard could not update ${currentConfigState.configPath}: ${written.error}`, "error");
					return false;
				}
				currentPolicySettings(ctx);
				return true;
			};
			const enable = (): void => {
				if (!persist(true)) return;
				store.pause.resume();
				syncBypassStatus(ctx);
				ctx.ui.notify(
					hasTypeSafeCredentials(typeSafeTransport.env)
						? `TypeSafe review enabled and saved to ${currentConfigState.configPath}. Known-risk blocks now include an advisory reason check; approval is unchanged.`
						: `TypeSafe review enabled and saved to ${currentConfigState.configPath}, but ${TYPESAFE_API_KEY_ENV} is not set. Reviews will report missing credentials until Pi is restarted with the variable set.`,
					hasTypeSafeCredentials(typeSafeTransport.env) ? "info" : "warning",
				);
			};
			const disable = (): void => {
				if (!persist(false)) return;
				store.clear();
				store.pause.resume();
				syncBypassStatus(ctx);
				ctx.ui.notify(`TypeSafe review disabled and saved to ${currentConfigState.configPath}. No TypeSafe requests will be made.`, "info");
			};
			const pause = (durationMs: number): void => {
				store.pause.pause(durationMs);
				store.clear();
				syncBypassStatus(ctx);
				ctx.ui.notify(`TypeSafe review paused for ${formatDuration(durationMs)} in this session; the guard itself is unchanged.`, "info");
			};
			const resume = (): void => {
				store.pause.resume();
				syncBypassStatus(ctx);
				ctx.ui.notify("TypeSafe review resumed.", "info");
			};
			const selectDuration = async (): Promise<number | undefined> => {
				const duration = await ctx.ui.select(
					"Pause TypeSafe review for…",
					DURATION_OPTIONS.map((option) => option.label),
				);
				return DURATION_OPTIONS.find((candidate) => candidate.label === duration)?.value;
			};

			if ((action === "" && !interactive) || action === "status") {
				ctx.ui.notify(`infra-command-guard — ${describeTypeSafeState()}`, "info");
				return;
			}
			if (action === "enable") {
				enable();
				return;
			}
			if (action === "disable") {
				disable();
				return;
			}
			if (action === "resume") {
				resume();
				return;
			}
			if (action === "pause") {
				if (!currentTypeSafeSettings.enabled) {
					ctx.ui.notify(`TypeSafe review is already disabled in configuration; run /${TYPESAFE_COMMAND} enable first.`, "info");
					return;
				}
				const durationArgument = rest.join(" ");
				let durationMs = durationArgument ? parseDurationArgument(durationArgument) : undefined;
				if (durationArgument && durationMs === undefined) {
					ctx.ui.notify(`Unknown pause duration "${durationArgument}". ${TYPESAFE_USAGE}`, "warning");
					return;
				}
				if (durationMs === undefined) {
					if (!interactive) {
						ctx.ui.notify(TYPESAFE_USAGE, "warning");
						return;
					}
					durationMs = await selectDuration();
					if (durationMs === undefined) return;
				}
				pause(durationMs);
				return;
			}
			if (action !== "") {
				ctx.ui.notify(TYPESAFE_USAGE, "warning");
				return;
			}

			const enableOption = "Enable TypeSafe review (saves to configuration)";
			const disableOption = "Disable TypeSafe review (saves to configuration)";
			const pauseOption = "Pause TypeSafe review…";
			const resumeOption = "Resume TypeSafe review now";
			const options = currentConfigState.error
				? []
				: !currentTypeSafeSettings.enabled
					? [enableOption]
					: [store.pause.isPaused() ? resumeOption : pauseOption, disableOption];
			if (options.length === 0) {
				ctx.ui.notify(`infra-command-guard — ${describeTypeSafeState()}`, "error");
				return;
			}
			const choice = await ctx.ui.select(describeTypeSafeState(), options);
			if (!choice) return;
			if (choice === enableOption) enable();
			else if (choice === disableOption) disable();
			else if (choice === resumeOption) resume();
			else if (choice === pauseOption) {
				const durationMs = await selectDuration();
				if (durationMs !== undefined) pause(durationMs);
			}
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
		async execute(_toolCallId, params, signal, _onUpdate, ctx) {
			currentPolicySettings(ctx);
			const approvalStore = currentApprovals();
			const validation = approvalStore.validate(params.request_id, params.command, params.reason);
			if (!validation.ok) {
				return {
					content: [{ type: "text", text: validation.error }],
					details: { approved: false, requestId: params.request_id, reason: params.reason, command: params.command },
				};
			}
			// A cancelled tool call must never notify the user or open the overlay.
			// The pending request stays valid so a fresh call can still ask.
			const cancelled = () => ({
				content: [{ type: "text" as const, text: "Approval request cancelled before the user was asked. Do not retry the command." }],
				details: { approved: false, requestId: validation.pending.id, reason: params.reason, command: params.command },
			});
			if (signal?.aborted) return cancelled();

			if (ctx.mode !== "tui") {
				return {
					content: [{ type: "text", text: "Cannot approve: TUI approval UI is not available. Do not retry the command." }],
					details: { approved: false, requestId: validation.pending.id, reason: params.reason, command: params.command },
				};
			}

			const blockedIdentity = validation.pending.identity;
			const bypassOffer = findMatchingBypassRule(blockedIdentity, currentPolicySettings(ctx));
			const bypassOfferConfig =
				bypassOffer
					? {
						executable: bypassOffer.executable,
						scope: bypassOffer.scope,
						cwd: blockedIdentity.cwd,
					}
					: undefined;
			const bypassDescription = bypassOfferConfig
				? describeBypassScope(bypassOfferConfig.executable, bypassOfferConfig.scope)
				: undefined;
			const approvalDetails = bypassOfferConfig
				? {
					summary: params.summary,
					flags: [
						...params.flags,
						{
							...BYPASS_OFFER_FLAG,
							meaning: bypassOfferConfig.scope.kind === "kubectl-kubeconfig"
								? `Choosing bypass trusts every guarded kubectl command that explicitly uses the exact kubeconfig ${bypassOfferConfig.scope.path}, without approval, while commands run in ${bypassOfferConfig.cwd} or its subdirectories for the selected duration. Other kubeconfigs, directories, guarded tools, and non-bypassable kubectl capabilities remain guarded.`
								: `Choosing bypass trusts ${bypassDescription} and trailing arguments without approval while commands run in ${bypassOfferConfig.cwd} or its subdirectories for the selected duration. Other directories and commands remain guarded.`,
						},
					],
					blastRadius: params.blastRadius,
				}
				: { summary: params.summary, flags: params.flags, blastRadius: params.blastRadius };

			// Bounded by the review's own timeout and by this call's abort signal;
			// failures surface in the overlay and never delay or replace the normal
			// approval decision.
			const advisory = await typeSafeAdvisory(validation.pending, ctx, signal);
			if (signal?.aborted) return cancelled();
			await requestApprovalAttention(ctx);
			const approvalChoice = await requestInfraApproval(
				ctx,
				approvalDetails,
				params.reason,
				params.command,
				bypassOfferConfig
					? {
						label: `Approve & bypass ${bypassDescription} in this directory for…`,
						onSelect: async (select) => {
							const duration = await select(
								"Bypass duration",
								DURATION_OPTIONS.map((option) => option.label),
							);
							const option = DURATION_OPTIONS.find((candidate) => candidate.label === duration);
							if (!option) return false;
							const refreshedSettings = currentPolicySettings(ctx);
							const refreshedValidation = approvalStore.validate(
								validation.pending.id,
								params.command,
								params.reason,
							);
							const refreshedOffer = refreshedValidation.ok
								? findMatchingBypassRule(refreshedValidation.pending.identity, refreshedSettings)
								: undefined;
							if (
								!refreshedValidation.ok ||
								!refreshedOffer ||
								refreshedOffer.executable !== bypassOfferConfig.executable ||
								refreshedValidation.pending.identity.cwd !== bypassOfferConfig.cwd ||
								!sameBypassScope(refreshedOffer.scope, bypassOfferConfig.scope)
							) {
								ctx.ui.notify("Bypass request expired or changed. Run the blocked command again.", "warning");
								return false;
							}
							currentBypasses().addRule(
								bypassOfferConfig.executable,
								bypassOfferConfig.cwd,
								bypassOfferConfig.scope,
								option.value,
							);
							syncBypassStatus(ctx);
							ctx.ui.notify(
								`Bypass active for ${formatDuration(option.value)}: ${bypassDescription} in ${bypassOfferConfig.cwd}`,
								"warning",
							);
							return true;
						},
					}
					: undefined,
				advisory,
			);
			if (approvalChoice === "cancel") {
				approvalStore.cancel(validation.pending.id);
				return {
					content: [{ type: "text", text: "User cancelled. Do not retry the command." }],
					details: { approved: false, requestId: validation.pending.id, reason: params.reason, command: params.command },
				};
			}
			if (approvalChoice === "bypass") {
				approvalStore.clear();
				return {
					content: [{ type: "text", text: "Bypass active. Retry the exact same command with the same execution context now." }],
					details: {
						approved: true,
						bypass: true,
						requestId: validation.pending.id,
						reason: params.reason,
						command: params.command,
					},
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
		syncBypassStatus(ctx);
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
			currentBypasses(),
		);
		beginTypeSafeReview(guarded, identity.command, ctx);
		return guarded.allow ? undefined : { block: true, reason: guarded.reason };
	});

	pi.registerTool({
		...bashTool,
		execute: async (toolCallId, params, signal, onUpdate, ctx) => {
			syncBypassStatus(ctx);
			const cwd = ctx?.cwd ?? process.cwd();
			const identity = executionIdentity("bash", params, cwd);
			const delegatedTool = createBashTool(identity?.cwd ?? cwd);
			if (!identity) return delegatedTool.execute(toolCallId, params, signal, onUpdate);
			const policySettings = currentPolicySettings(ctx);
			const guarded = guardExecution(
				currentApprovals(),
				identity,
				ctx.mode,
				policySettings,
				currentBypasses(),
			);
			beginTypeSafeReview(guarded, identity.command, ctx);
			if (!guarded.allow) throw new Error(guarded.reason);
			return delegatedTool.execute(toolCallId, params, signal, onUpdate);
		},
	});

	pi.on("session_shutdown", () => {
		typeSafeReviews.clear();
		if (events[APPROVAL_STORE_KEY] === approvals) delete events[APPROVAL_STORE_KEY];
		if (events[BYPASS_STORE_KEY] === bypasses) delete events[BYPASS_STORE_KEY];
		if (events[TYPESAFE_STORE_KEY] === typeSafeReviews) delete events[TYPESAFE_STORE_KEY];
	});
}

import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import {
	DEFAULT_GUARD_SETTINGS,
	hasEnabledGuards,
	type GuardSettings,
} from "./guarded-executables.ts";
import { evaluateCommand, isInteractiveInterpreterCommand } from "./policy.ts";

const APPROVAL_STORE_KEY = Symbol.for("infra-command-guard.approval-store.v1");
const APPROVAL_TTL_MS = 10 * 60 * 1000;

type GuardSource = "bash" | "exec-command" | "code-mode-exec-command";

interface ExecutionIdentity {
	source: GuardSource;
	command: string;
	cwd: string;
	shell?: string | undefined;
	tty: boolean;
	login?: boolean | undefined;
}

interface PendingApproval {
	id: string;
	identity: ExecutionIdentity;
	reason: string;
	createdAt: number;
}

function executionFingerprint(identity: ExecutionIdentity): string {
	return JSON.stringify([
		identity.source,
		identity.command,
		identity.cwd,
		identity.shell ?? null,
		identity.tty,
		identity.login ?? null,
	]);
}

function executionIdentity(
	source: GuardSource,
	input: unknown,
	baseCwd: string,
): ExecutionIdentity | undefined {
	if (!input || typeof input !== "object") return undefined;
	const record = input as Record<string, unknown>;
	const commandValue = source === "bash" ? record.command : (record.cmd ?? record.command);
	if (typeof commandValue !== "string" || commandValue.length === 0) return undefined;
	const workdirValue = record.workdir ?? record.cwd ?? record.working_directory;
	const workdir = typeof workdirValue === "string" ? workdirValue : undefined;
	return {
		source,
		command: commandValue,
		cwd: workdir ? resolve(baseCwd, workdir) : resolve(baseCwd),
		shell: typeof record.shell === "string" ? record.shell : undefined,
		tty: record.tty === true,
		login: typeof record.login === "boolean" ? record.login : undefined,
	};
}

class ApprovalStore {
	private readonly pending = new Map<string, PendingApproval>();
	private readonly approved = new Map<string, { count: number; expiresAt: number }>();

	constructor(
		private readonly now: () => number = Date.now,
		private readonly createId: () => string = randomUUID,
	) {}

	createPending(identity: ExecutionIdentity, reason: string): PendingApproval {
		this.prune();
		const pending = {
			id: this.createId(),
			identity: { ...identity },
			reason,
			createdAt: this.now(),
		};
		this.pending.set(pending.id, pending);
		return pending;
	}

	validate(requestId: string, command: string, reason: string): { ok: true; pending: PendingApproval } | { ok: false; error: string } {
		this.prune();
		const pending = this.pending.get(requestId);
		if (!pending) return { ok: false, error: "Approval request is missing or expired. Retry the blocked shell call to create a new request." };
		if (pending.identity.command !== command) {
			return { ok: false, error: "Approval request does not match the exact blocked command. Do not retry the command." };
		}
		if (pending.reason !== reason) {
			return { ok: false, error: "Approval request does not match the guard reason. Do not retry the command." };
		}
		return { ok: true, pending };
	}

	approve(requestId: string, command: string, reason: string): { ok: true } | { ok: false; error: string } {
		const validation = this.validate(requestId, command, reason);
		if (!validation.ok) return validation;
		this.pending.delete(validation.pending.id);
		const key = executionFingerprint(validation.pending.identity);
		const current = this.approved.get(key);
		this.approved.set(key, {
			count: (current?.count ?? 0) + 1,
			expiresAt: this.now() + APPROVAL_TTL_MS,
		});
		return { ok: true };
	}

	cancel(requestId: string): void {
		this.pending.delete(requestId);
	}

	clear(): void {
		this.pending.clear();
		this.approved.clear();
	}

	consume(identity: ExecutionIdentity): boolean {
		this.prune();
		const key = executionFingerprint(identity);
		const approval = this.approved.get(key);
		if (!approval || approval.count <= 0) return false;
		if (approval.count === 1) this.approved.delete(key);
		else this.approved.set(key, { ...approval, count: approval.count - 1 });
		return true;
	}

	private prune(): void {
		const now = this.now();
		for (const [id, pending] of this.pending) {
			if (pending.createdAt + APPROVAL_TTL_MS <= now) this.pending.delete(id);
		}
		for (const [key, approval] of this.approved) {
			if (approval.expiresAt <= now) this.approved.delete(key);
		}
	}
}

function formatApprovalRequest(reason: string, command: string, requestId: string): string {
	return [
		`BLOCKED — ${reason}`,
		`Command: ${command}`,
		`Approval request: ${requestId}`,
		"",
		"Before retrying, you MUST present this through the approve_infra_command tool",
		"(NOT a plain chat message). Follow these steps exactly:",
		"",
		"  1. Draft structured, plain-language approval details:",
		"       • summary: what the command does, without repeating the command text",
		"       • flags: each important flag/option and what it changes",
		"       • blastRadius: what changes, what data is exposed, and worst-case impact",
		"",
		"  2. Call approve_infra_command with:",
		"       • request_id: the approval request identifier above",
		"       • command: the EXACT command byte-for-byte, no edits",
		"       • reason: the guard reason above",
		"       • summary, flags, and blastRadius as separate fields",
		"",
		'  3. If the user selects "Approve and run", retry the original shell tool',
		"     with the EXACT command byte-for-byte, no edits.",
		'  4. If the user selects "Cancel" or anything else, stop — do not retry.',
		"  5. Do NOT explain in chat first; the approval details must live inside",
		"     the approval UI so the user can review and approve in one place.",
	].join("\n");
}

function guardExecution(
	store: ApprovalStore,
	identity: ExecutionIdentity,
	mode: string | undefined,
	guardSettings: GuardSettings = DEFAULT_GUARD_SETTINGS,
): { allow: true } | { allow: false; reason: string; requestId?: string | undefined } {
	if (hasEnabledGuards(guardSettings) && identity.tty && isInteractiveInterpreterCommand(identity.command)) {
		return {
			allow: false,
			reason:
				"BLOCKED — interactive shell and interpreter sessions are not supported by infra-command-guard because later write_stdin input cannot be classified reliably. Run a complete non-interactive command instead.",
		};
	}
	if (store.consume(identity)) return { allow: true };
	const decision = evaluateCommand(identity.command, guardSettings);
	if (decision.allow) return { allow: true };
	if (mode !== "tui") {
		return {
			allow: false,
			reason: [
				`BLOCKED — ${decision.reason}`,
				`Command: ${identity.command}`,
				"",
				"Approval is unavailable outside TUI mode. Do not retry the command.",
			].join("\n"),
		};
	}
	const pending = store.createPending(identity, decision.reason);
	return {
		allow: false,
		requestId: pending.id,
		reason: formatApprovalRequest(decision.reason, identity.command, pending.id),
	};
}

export {
	APPROVAL_STORE_KEY,
	executionFingerprint,
	executionIdentity,
	ApprovalStore,
	guardExecution,
};
export type { ExecutionIdentity, GuardSource };

import { homedir } from "node:os";
import { resolve, sep } from "node:path";
import type { CommandPolicySettings, GuardedExecutable } from "./guarded-executables.ts";
import { evaluateCommand } from "./policy.ts";
import { extractInvocation, parseSimpleCommands, type Invocation } from "./shell.ts";
import { evaluateNonBypassableRisk, normalizeOverrideArguments } from "./tool-policies.ts";
import type { ExecutionIdentity } from "./approvals.ts";

const TEN_MINUTES_MS = 10 * 60 * 1000;
const THIRTY_MINUTES_MS = 30 * 60 * 1000;
const ONE_HOUR_MS = 60 * 60 * 1000;

const DURATION_OPTIONS = [
	{ label: "10 minutes", value: TEN_MINUTES_MS },
	{ label: "30 minutes", value: THIRTY_MINUTES_MS },
	{ label: "1 hour", value: ONE_HOUR_MS },
] as const;

const BYPASSABLE_EXECUTABLES = [
	"argocd",
	"aws",
	"az",
	"docker",
	"find",
	"gcloud",
	"git",
	"helm",
	"kubectl",
	"rm",
	"rmdir",
	"rsync",
	"shred",
	"terraform",
	"truncate",
	"unlink",
	"vault",
] as const satisfies readonly GuardedExecutable[];

type BypassRule = {
	executable: GuardedExecutable;
	cwd: string;
	prefix: readonly string[];
	expiresAt: number;
};

type MatchingInvocation = {
	executable: GuardedExecutable;
	args: string[];
	normalizedPrefix: string[];
};

function formatDuration(durationMs: number): string {
	const option = DURATION_OPTIONS.find((candidate) => candidate.value === durationMs);
	if (option) return option.label;
	const minutes = Math.max(1, Math.round(durationMs / 60000));
	return `${minutes} minute${minutes === 1 ? "" : "s"}`;
}

function expandHomePath(path: string): string {
	if (path === "~") return homedir();
	if (path.startsWith(`~${sep}`) || path.startsWith("~/") || path.startsWith("~\\")) {
		return resolve(homedir(), path.slice(2));
	}
	return path;
}

function isPathWithin(candidate: string, directory: string): boolean {
	return candidate === directory || candidate.startsWith(directory.endsWith(sep) ? directory : directory + sep);
}

class GuardBypassStore {
	private pauseExpiresAt: number | undefined;
	private readonly rules: BypassRule[] = [];

	constructor(private readonly now: () => number = Date.now) {}

	pause(durationMs: number): void {
		this.pauseExpiresAt = this.now() + durationMs;
	}

	resume(): void {
		this.pauseExpiresAt = undefined;
	}

	isPaused(): boolean {
		this.prune();
		return this.pauseExpiresAt !== undefined;
	}

	addRule(executable: GuardedExecutable, cwd: string, prefix: readonly string[], durationMs: number): BypassRule {
		this.prune();
		const existing = this.rules.find(
			(rule) =>
				rule.executable === executable &&
				rule.cwd === cwd &&
				rule.prefix.length === prefix.length &&
				rule.prefix.every((token, index) => token === prefix[index]),
		);
		if (existing) {
			existing.expiresAt = this.now() + durationMs;
			return existing;
		}
		const rule = { executable, cwd, prefix: [...prefix], expiresAt: this.now() + durationMs };
		this.rules.push(rule);
		return rule;
	}

	removeRule(rule: BypassRule): boolean {
		const index = this.rules.indexOf(rule);
		if (index === -1) return false;
		this.rules.splice(index, 1);
		return true;
	}

	listRules(): readonly BypassRule[] {
		this.prune();
		return [...this.rules];
	}

	clear(): void {
		this.pauseExpiresAt = undefined;
		this.rules.length = 0;
	}

	matches(executable: GuardedExecutable, cwd: string, args: readonly string[]): boolean {
		this.prune();
		for (const rule of this.rules) {
			if (rule.executable !== executable) continue;
			if (!isPathWithin(cwd, rule.cwd)) continue;
			if (args.length < rule.prefix.length) continue;
			if (rule.prefix.every((token, index) => token === args[index])) return true;
		}
		return false;
	}

	describe(): string[] {
		this.prune();
		const lines: string[] = [];
		if (this.pauseExpiresAt !== undefined) {
			lines.push(`Guard paused for ${formatDuration(this.pauseExpiresAt - this.now())}`);
		}
		for (const rule of this.rules) {
			lines.push(this.describeRule(rule));
		}
		return lines;
	}

	describeRule(rule: BypassRule): string {
		return `${rule.executable} ${rule.prefix.join(" ")} in ${rule.cwd} — bypassed for ${formatDuration(rule.expiresAt - this.now())}`;
	}

	private prune(): void {
		const now = this.now();
		if (this.pauseExpiresAt !== undefined && this.pauseExpiresAt <= now) this.pauseExpiresAt = undefined;
		for (let index = this.rules.length - 1; index >= 0; index -= 1) {
			if (this.rules[index].expiresAt <= now) this.rules.splice(index, 1);
		}
	}
}

const PATH_SCOPED_OPTION_NAMES = new Set([
	"--ca-file",
	"--cacert",
	"--cert",
	"--cert-file",
	"--client-certificate",
	"--client-key",
	"--credentials-file",
	"--env-file",
	"--kubeconfig",
	"--key",
	"--key-file",
	"--server",
	"--tls-ca-cert",
	"--tls-cert",
	"--tls-key",
]);

function normalizeBypassTokens(executable: GuardedExecutable, args: readonly string[]): string[] {
	const rawTokens = normalizeOverrideArguments(executable, [...args], PATH_SCOPED_OPTION_NAMES);
	return rawTokens.map((token) => {
		const equalsIndex = token.indexOf("=");
		if (equalsIndex !== -1) {
			const value = token.slice(equalsIndex + 1);
			if (value.includes("/") || value.startsWith("~")) {
				return `${token.slice(0, equalsIndex + 1)}${expandHomePath(value)}`;
			}
			return token;
		}
		return token.includes("/") || token.startsWith("~") ? expandHomePath(token) : token;
	});
}

function invocationBypassCandidate(
	executable: GuardedExecutable,
	invocation: Invocation,
	settings: CommandPolicySettings,
): MatchingInvocation | undefined {
	const guardSettings = settings.guards;
	if (!guardSettings[executable]) return undefined;
	const decision = evaluateCommand([executable, ...invocation.args].join(" "), settings);
	if (decision.allow) return undefined;
	const nonBypassable = evaluateNonBypassableRisk(executable, invocation);
	if (nonBypassable && nonBypassable.basis !== "unclassified") return undefined;
	const normalizedPrefix = normalizeBypassTokens(executable, invocation.args);
	if (normalizedPrefix.length === 0) return undefined;
	return { executable, args: [...invocation.args], normalizedPrefix };
}

function findMatchingBypassRule(
	identity: ExecutionIdentity,
	settings: CommandPolicySettings,
): MatchingInvocation | undefined {
	const parsed = parseSimpleCommands(identity.command);
	if ("error" in parsed) return undefined;
	const candidates: MatchingInvocation[] = [];
	for (const segment of parsed.segments) {
		if (evaluateCommand(segment.bare, settings).allow) continue;
		const invocation = extractInvocation(segment.words);
		if ("error" in invocation || !invocation.executable) return undefined;
		const executable = invocation.executable as GuardedExecutable;
		if (!(BYPASSABLE_EXECUTABLES as readonly string[]).includes(executable)) return undefined;
		const match = invocationBypassCandidate(executable, invocation, settings);
		if (!match) return undefined;
		candidates.push(match);
	}
	return candidates.length === 1 ? candidates[0] : undefined;
}

export {
	BYPASSABLE_EXECUTABLES,
	DURATION_OPTIONS,
	ONE_HOUR_MS,
	TEN_MINUTES_MS,
	THIRTY_MINUTES_MS,
	GuardBypassStore,
	expandHomePath,
	findMatchingBypassRule,
	formatDuration,
	isPathWithin,
};
export type { BypassRule, MatchingInvocation };

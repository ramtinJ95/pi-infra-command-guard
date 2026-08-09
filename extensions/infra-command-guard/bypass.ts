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
	scope: BypassScope;
	expiresAt: number;
};

type BypassScope =
	| { kind: "command-prefix"; tokens: readonly string[] }
	| { kind: "kubectl-kubeconfig"; path: string };

type MatchingInvocation = {
	executable: GuardedExecutable;
	scope: BypassScope;
};

type KubectlKubeconfigResult =
	| { kind: "absent" }
	| { kind: "invalid" }
	| { kind: "scope"; scope: BypassScope & { kind: "kubectl-kubeconfig" } };

function formatDuration(durationMs: number): string {
	const option = DURATION_OPTIONS.find((candidate) => candidate.value === durationMs);
	if (option) return option.label;
	const minutes = Math.max(1, Math.round(durationMs / 60000));
	return `${minutes} minute${minutes === 1 ? "" : "s"}`;
}

function expandHomePath(path: string): string {
	if (path === "~" || path === "$HOME" || path === "${HOME}") return homedir();
	if (path.startsWith(`~${sep}`) || path.startsWith("~/") || path.startsWith("~\\")) {
		return resolve(homedir(), path.slice(2));
	}
	for (const prefix of ["$HOME/", "$HOME\\", "${HOME}/", "${HOME}\\"]) {
		if (path.startsWith(prefix)) return resolve(homedir(), path.slice(prefix.length));
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

	addRule(executable: GuardedExecutable, cwd: string, scope: BypassScope, durationMs: number): BypassRule {
		this.prune();
		const existing = this.rules.find(
			(rule) =>
				rule.executable === executable &&
				rule.cwd === cwd &&
				scopesEqual(rule.scope, scope),
		);
		if (existing) {
			existing.expiresAt = this.now() + durationMs;
			return existing;
		}
		const rule = { executable, cwd, scope: copyScope(scope), expiresAt: this.now() + durationMs };
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

	matches(executable: GuardedExecutable, cwd: string, scope: BypassScope): boolean {
		this.prune();
		for (const rule of this.rules) {
			if (rule.executable !== executable) continue;
			if (!isPathWithin(cwd, rule.cwd)) continue;
			if (scopeMatches(rule.scope, scope)) return true;
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
		return `${describeBypassScope(rule.executable, rule.scope)} in ${rule.cwd} — bypassed for ${formatDuration(rule.expiresAt - this.now())}`;
	}

	private prune(): void {
		const now = this.now();
		if (this.pauseExpiresAt !== undefined && this.pauseExpiresAt <= now) this.pauseExpiresAt = undefined;
		for (let index = this.rules.length - 1; index >= 0; index -= 1) {
			if (this.rules[index].expiresAt <= now) this.rules.splice(index, 1);
		}
	}
}

function copyScope(scope: BypassScope): BypassScope {
	return scope.kind === "command-prefix"
		? { kind: "command-prefix", tokens: [...scope.tokens] }
		: { ...scope };
}

function scopesEqual(left: BypassScope, right: BypassScope): boolean {
	if (left.kind !== right.kind) return false;
	if (left.kind === "kubectl-kubeconfig" && right.kind === "kubectl-kubeconfig") {
		return left.path === right.path;
	}
	if (left.kind === "command-prefix" && right.kind === "command-prefix") {
		return left.tokens.length === right.tokens.length &&
			left.tokens.every((token, index) => token === right.tokens[index]);
	}
	return false;
}

function sameBypassScope(left: BypassScope, right: BypassScope): boolean {
	return scopesEqual(left, right);
}

function scopeMatches(rule: BypassScope, candidate: BypassScope): boolean {
	if (rule.kind !== candidate.kind) return false;
	if (rule.kind === "kubectl-kubeconfig" && candidate.kind === "kubectl-kubeconfig") {
		return rule.path === candidate.path;
	}
	if (rule.kind === "command-prefix" && candidate.kind === "command-prefix") {
		return candidate.tokens.length >= rule.tokens.length &&
			rule.tokens.every((token, index) => token === candidate.tokens[index]);
	}
	return false;
}

function describeBypassScope(executable: GuardedExecutable, scope: BypassScope): string {
	if (scope.kind === "kubectl-kubeconfig") {
		return `all guarded kubectl commands using kubeconfig ${scope.path}`;
	}
	return `${executable} ${scope.tokens.join(" ")}`;
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

function kubectlKubeconfigScope(
	args: readonly string[],
	cwd: string,
	homeOverride: boolean,
): KubectlKubeconfigResult {
	let value: string | undefined;
	for (let index = 0; index < args.length; index += 1) {
		const token = args[index];
		if (token === "--") break;
		let candidate: string | undefined;
		if (token === "--kubeconfig") {
			candidate = args[index + 1];
			index += 1;
		} else if (token.startsWith("--kubeconfig=")) {
			candidate = token.slice("--kubeconfig=".length);
		}
		if (candidate === undefined) continue;
		if (value !== undefined || candidate.length === 0) return { kind: "invalid" };
		value = candidate;
	}
	if (value === undefined) return { kind: "absent" };
	if (isHomeReference(value) && homeOverride) return { kind: "invalid" };
	const expanded = expandHomePath(value);
	if (expanded.startsWith("~") || expanded.includes("$") || expanded.includes("\0")) return { kind: "invalid" };
	return { kind: "scope", scope: { kind: "kubectl-kubeconfig", path: resolve(cwd, expanded) } };
}

function isHomeReference(value: string): boolean {
	return value === "$HOME" || value === "${HOME}" || value.startsWith("$HOME/") || value.startsWith("${HOME}/");
}

function hasHomeOverride(words: readonly string[]): boolean {
	return words.some((word) => /^HOME=/.test(word));
}

function hasCwdChangingWrapper(invocation: Invocation, segmentWords: readonly string[]): boolean {
	if (!invocation.rawExecutable) return false;
	const executableIndex = segmentWords.indexOf(invocation.rawExecutable);
	if (executableIndex <= 0) return false;
	const wrapperWords = segmentWords.slice(0, executableIndex);
	return wrapperWords.some((word) => {
		const name = word.includes("=") ? word.slice(0, word.indexOf("=")) : word;
		return name === "-C" || name === "-D" || name === "--chdir";
	});
}

function invocationBypassCandidate(
	executable: GuardedExecutable,
	invocation: Invocation,
	settings: CommandPolicySettings,
	cwd: string,
	homeOverride: boolean,
): MatchingInvocation | undefined {
	const guardSettings = settings.guards;
	if (!guardSettings[executable]) return undefined;
	const decision = evaluateCommand([executable, ...invocation.args].join(" "), settings);
	if (decision.allow) return undefined;
	const nonBypassable = evaluateNonBypassableRisk(executable, invocation);
	if (nonBypassable && nonBypassable.basis !== "unclassified") return undefined;
	if (homeOverride && invocation.args.some(isHomeReference)) return undefined;
	if (executable === "kubectl") {
		const kubeconfig = kubectlKubeconfigScope(invocation.args, cwd, homeOverride);
		if (kubeconfig.kind === "invalid") return undefined;
		if (kubeconfig.kind === "scope") return { executable, scope: kubeconfig.scope };
	}
	const normalizedPrefix = normalizeBypassTokens(executable, invocation.args);
	if (normalizedPrefix.length === 0) return undefined;
	return { executable, scope: { kind: "command-prefix", tokens: normalizedPrefix } };
}

function findMatchingBypassRule(
	identity: ExecutionIdentity,
	settings: CommandPolicySettings,
): MatchingInvocation | undefined {
	const parsed = parseSimpleCommands(identity.command);
	if ("error" in parsed) return undefined;
	const candidates: MatchingInvocation[] = [];
	let cwdUncertain = false;
	let homeOverride = false;
	for (const segment of parsed.segments) {
		const invocation = extractInvocation(segment.words);
		if ("error" in invocation || !invocation.executable) return undefined;
		homeOverride ||= hasHomeOverride(segment.words);
		const segmentChangesCwd = invocation.executable === "cd" || invocation.executable === "pushd" || invocation.executable === "popd";
		if (evaluateCommand(segment.bare, settings).allow) {
			cwdUncertain ||= segmentChangesCwd;
			continue;
		}
		if (cwdUncertain || segmentChangesCwd || hasCwdChangingWrapper(invocation, segment.words)) return undefined;
		const executable = invocation.executable as GuardedExecutable;
		if (!(BYPASSABLE_EXECUTABLES as readonly string[]).includes(executable)) return undefined;
		const match = invocationBypassCandidate(executable, invocation, settings, identity.cwd, homeOverride);
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
	describeBypassScope,
	expandHomePath,
	findMatchingBypassRule,
	formatDuration,
	isPathWithin,
	sameBypassScope,
};
export type { BypassRule, BypassScope, MatchingInvocation };

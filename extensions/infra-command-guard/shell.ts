import { parse, type Command, type Function as BashFunction, type ParsedScript, type Word } from "unbash";
import { GUARDED_EXECUTABLES } from "./guarded-executables.ts";

const GUARDED_PATTERNS = new Map<string, RegExp>();
const DEFAULT_GUARDED_PATTERN = new RegExp(`\\b(?:${GUARDED_EXECUTABLES.join("|")})\\b`, "i");

type ShellSegment = {
	words: string[];
	rawWords: string[];
	bare: string;
	shadowedExecutable?: string;
	forwardedWords?: string[];
	forwardedBare?: string;
};
type ParsedCommands =
	| { segments: ShellSegment[]; error?: undefined }
	| { segments?: undefined; error: string };
type RecoveredCommands = {
	segments: ShellSegment[];
	errors: string[];
	hasDynamicExecutable: boolean;
};
type OptionClassification = "boolean" | "value" | "unknown";
type ConsumedOptions =
	| { index: number; error?: undefined }
	| { index?: undefined; error: string };
type CollectedPositionals =
	| { positionals: string[]; error?: undefined }
	| { positionals?: undefined; error: string };
type Invocation = {
	executable: string | null;
	rawExecutable?: string;
	args: string[];
	words: string[];
	wrappers: string[];
	error?: undefined;
};
type InvocationResult = Invocation | { error: string; executable?: undefined; args?: undefined; words?: undefined; wrappers?: undefined };

const SHELL_RUNNERS = new Set([
	"sh",
	"bash",
	"zsh",
	"dash",
	"fish",
	"xargs",
	"python",
	"python3",
	"python3.11",
	"python3.12",
	"node",
	"perl",
	"ruby",
]);

const ENV_BOOLEAN_OPTIONS = new Set(["-0", "-i", "--ignore-environment", "--null"]);
const ENV_VALUE_OPTIONS = new Set(["-C", "-S", "-u", "--chdir", "--split-string", "--unset"]);

const SUDO_BOOLEAN_OPTIONS = new Set([
	"-A",
	"-E",
	"-H",
	"-K",
	"-k",
	"-n",
	"-S",
	"-V",
	"-b",
	"-l",
	"-s",
	"-v",
	"--askpass",
	"--edit",
	"--list",
	"--non-interactive",
	"--preserve-env",
	"--remove-timestamp",
	"--reset-timestamp",
	"--shell",
	"--stdin",
	"--validate",
	"--version",
]);

const SUDO_VALUE_OPTIONS = new Set([
	"-C",
	"-D",
	"-R",
	"-T",
	"-U",
	"-g",
	"-h",
	"-p",
	"-r",
	"-t",
	"-u",
	"--chdir",
	"--close-from",
	"--group",
	"--host",
	"--other-user",
	"--prompt",
	"--role",
	"--type",
	"--user",
]);

const TIME_BOOLEAN_OPTIONS = new Set(["-p", "-v", "--portability", "--verbose"]);
const TIME_VALUE_OPTIONS = new Set(["-f", "-o", "--format", "--output"]);

const SHELL_CONTROL_KEYWORDS = new Set([
	"!",
	"if",
	"then",
	"elif",
	"else",
	"fi",
	"for",
	"while",
	"until",
	"do",
	"done",
	"case",
	"esac",
	"select",
	"function",
]);

const SHELL_EXECUTION_BUILTINS = new Set([".", "source", "eval", "exec"]);
const INTERACTIVE_INTERPRETERS = new Set(["bash", "dash", "fish", "node", "perl", "ruby", "sh", "zsh"]);

function stripPath(raw: string): string {
	const normalized = String(raw || "");
	const parts = normalized.split(/[\\/]/);
	return (parts[parts.length - 1] || normalized).toLowerCase();
}

function isAssignmentWord(word: string): boolean {
	return /^[A-Za-z_][A-Za-z0-9_]*=.*/.test(word);
}

function normalizeForInfraScan(text: string): string {
	return String(text || "").replace(/["'\\]/g, "");
}

function containsGuardedText(
	text: string,
	guardedExecutables: readonly string[] = GUARDED_EXECUTABLES,
): boolean {
	if (guardedExecutables.length === 0) return false;
	if (guardedExecutables === GUARDED_EXECUTABLES) {
		return DEFAULT_GUARDED_PATTERN.test(normalizeForInfraScan(text));
	}
	const key = guardedExecutables.join("\0");
	let pattern = GUARDED_PATTERNS.get(key);
	if (!pattern) {
		pattern = new RegExp(`\\b(?:${guardedExecutables.join("|")})\\b`, "i");
		GUARDED_PATTERNS.set(key, pattern);
	}
	return pattern.test(normalizeForInfraScan(text));
}

function hasDynamicExecutable(command: string): boolean {
	if (!String(command || "").includes("$")) return false;
	const parsed = parseSimpleCommands(command);
	const recovered = requiresAstRecovery(parsed) ? recoverAstCommands(command) : undefined;
	if (recovered?.hasDynamicExecutable) return true;
	const segments = recovered?.segments ?? ("error" in parsed ? [] : parsed.segments);
	return segmentsHaveDynamicExecutable(segments);
}

function segmentsHaveDynamicExecutable(segments: readonly ShellSegment[]): boolean {
	for (const segment of segments) {
		const invocation = extractInvocation(segment.words);
		if (!("error" in invocation) && invocation.executable?.includes("$")) return true;
	}
	return false;
}

function requiresAstRecovery(parsed: ParsedCommands): boolean {
	if ("error" in parsed) return true;
	return parsed.segments.some((segment) => {
		const invocation = extractInvocation(segment.words);
		return !("error" in invocation) && invocation.executable !== null && SHELL_CONTROL_KEYWORDS.has(invocation.executable);
	});
}

function unquotedWordText(word: Word): string {
	if (!word.parts) return word.value;
	return word.parts
		.filter((part) => part.type === "Literal")
		.map((part) => part.value)
		.join("");
}

function commandSegment(command: Command, shadowed: boolean, executesArguments: boolean): ShellSegment | undefined {
	if (!command.name) return undefined;
	const prefixWords = command.prefix.map((assignment) => assignment.text);
	const commandWords = [command.name, ...command.suffix];
	const directExecutable = command.name.value;
	return {
		words: [...prefixWords, ...commandWords.map((word) => word.value)],
		rawWords: [...prefixWords, ...commandWords.map((word) => word.text)],
		bare: [...prefixWords, ...commandWords.map(unquotedWordText)].join(" "),
		shadowedExecutable: shadowed && !directExecutable.includes("/") ? stripPath(directExecutable) : undefined,
		forwardedWords: shadowed && executesArguments ? command.suffix.map((word) => word.value) : undefined,
		forwardedBare: shadowed && executesArguments ? command.suffix.map(unquotedWordText).join(" ") : undefined,
	};
}

const POSITIONAL_PARAMETER_PATTERN = /\$(?:[@*]|[1-9][0-9]*|\{(?:[@*]|[1-9][0-9]*)[^}]*\})/;

function commandExecutesArguments(command: Command): boolean {
	if (!command.name) return false;
	const rawWords = [command.name, ...command.suffix].map((word) => word.text);
	if (!rawWords.some((word) => POSITIONAL_PARAMETER_PATTERN.test(word))) return false;
	const invocation = extractInvocation([command.name.value, ...command.suffix.map((word) => word.value)]);
	if ("error" in invocation || !invocation.executable) return true;
	if (POSITIONAL_PARAMETER_PATTERN.test(invocation.rawExecutable ?? invocation.executable)) return true;
	if (SHELL_EXECUTION_BUILTINS.has(invocation.executable) || SHELL_RUNNERS.has(invocation.executable)) return true;
	return invocation.executable === "find" && invocation.args.some((word) => ["-exec", "-execdir", "-ok", "-okdir"].includes(word));
}

function functionExecutesArguments(
	value: unknown,
	activeFunctions: ReadonlyMap<string, BashFunction>,
	checkingFunctions = new Set<BashFunction>(),
): boolean {
	if (!value || typeof value !== "object") return false;
	const record = value as Record<string, unknown>;
	if (record.type === "Command") {
		const command = value as Command;
		if (commandExecutesArguments(command)) return true;
		const target = command.name ? activeFunctions.get(command.name.value) : undefined;
		if (!target || checkingFunctions.has(target)) return false;
		checkingFunctions.add(target);
		const executesArguments = functionExecutesArguments(target.body, activeFunctions, checkingFunctions);
		checkingFunctions.delete(target);
		return executesArguments;
	}
	for (const child of Object.values(record)) {
		if (functionExecutesArguments(child, activeFunctions, checkingFunctions)) return true;
	}
	return false;
}

function commandMayMutateFunctions(
	value: unknown,
	activeFunctions: ReadonlyMap<string, BashFunction>,
	checkingFunctions = new Set<BashFunction>(),
): boolean {
	if (!value || typeof value !== "object") return false;
	const record = value as Record<string, unknown>;
	if (record.type === "Function") return true;
	if (record.type === "Command") {
		const command = value as Command;
		if (!command.name) return false;
		const directName = command.name.value;
		const target = activeFunctions.get(directName);
		if (target) {
			if (checkingFunctions.has(target)) return false;
			checkingFunctions.add(target);
			const mayMutate = commandMayMutateFunctions(target.body, activeFunctions, checkingFunctions);
			checkingFunctions.delete(target);
			return mayMutate;
		}
		const invocation = staticShellBuiltinDispatch(command);
		if (!invocation) return false;
		const name = invocation.name;
		if (name.includes("$")) return true;
		if (name === "." || name === "eval" || name === "source" || name === "trap" || name === "unset") return true;
		return false;
	}
	for (const child of Object.values(record)) {
		if (commandMayMutateFunctions(child, activeFunctions, checkingFunctions)) return true;
	}
	return false;
}

function staticShellBuiltinDispatch(command: Command): { name: string; args: string[] } | undefined {
	if (!command.name) return undefined;
	const words = [command.name.value, ...command.suffix.map((word) => word.value)];
	let index = 0;
	while (words[index] === "builtin" || words[index] === "command") {
		const wrapper = words[index];
		index += 1;
		while (words[index] === "--" || (wrapper === "command" && words[index] === "-p")) index += 1;
		if (wrapper === "command" && (words[index] === "-v" || words[index] === "-V")) return undefined;
	}
	const name = words[index];
	return name ? { name, args: words.slice(index + 1) } : undefined;
}

function removeUnsetFunctions(words: readonly string[], activeFunctions: Map<string, BashFunction>): void {
	const variableOnly = words.some((word) => word === "-v" || word === "--variable");
	const functionMode = words.some((word) => word === "-f" || word === "--function");
	if (variableOnly && !functionMode) return;
	for (const word of words) {
		if (word === "--" || word.startsWith("-")) continue;
		if (word.includes("$")) {
			activeFunctions.clear();
			return;
		}
		activeFunctions.delete(word);
	}
}

function markDefinitelyShadowedCommands(
	script: ParsedScript,
	shadowedCommands: WeakSet<Command>,
	argumentForwardingCommands: WeakSet<Command>,
): void {
	const activeFunctions = new Map<string, BashFunction>();
	for (const statement of script.commands) {
		const node = statement.command;
		if (node.type === "Function") {
			const name = node.name.value;
			if (name && !name.includes("/")) activeFunctions.set(name, node);
			continue;
		}
		if (node.type !== "Command") {
			if (commandMayMutateFunctions(node, activeFunctions)) activeFunctions.clear();
			continue;
		}
		if (!node.name) continue;
		const name = node.name.value;
		const activeFunction = activeFunctions.get(name);
		if (activeFunction && !name.includes("/")) {
			shadowedCommands.add(node);
			if (functionExecutesArguments(activeFunction.body, activeFunctions)) argumentForwardingCommands.add(node);
			if (commandMayMutateFunctions(activeFunction.body, activeFunctions)) activeFunctions.clear();
			continue;
		}
		const invocation = staticShellBuiltinDispatch(node);
		if (invocation?.name === "unset") removeUnsetFunctions(invocation.args, activeFunctions);
		else if (invocation && [".", "eval", "source", "trap"].includes(invocation.name)) {
			activeFunctions.clear();
		}
	}
}

/**
 * Recover executable command nodes from Bash syntax that the provenance parser
 * deliberately does not support. unbash supplies the structural AST; argv and
 * wrapper normalization remain owned by the existing parser helpers.
 */
function recoverAstCommands(command: string): RecoveredCommands {
	const segments: ShellSegment[] = [];
	const errors: string[] = [];
	let hasDynamic = false;
	const seen = new WeakSet<object>();
	const shadowedCommands = new WeakSet<Command>();
	const argumentForwardingCommands = new WeakSet<Command>();

	const visit = (value: unknown): void => {
		if (!value || typeof value !== "object" || seen.has(value)) return;
		seen.add(value);
		const record = value as Record<string, unknown>;

		if (record.type === "Command") {
			const shellCommand = value as Command;
			const segment = commandSegment(
				shellCommand,
				shadowedCommands.has(shellCommand),
				argumentForwardingCommands.has(shellCommand),
			);
			if (segment) {
				segments.push(segment);
				const invocation = extractInvocation(segment.words);
				if (!("error" in invocation) && invocation.executable?.includes("$")) hasDynamic = true;
			}
		}

		if (record.type === "Script") {
			const script = value as ParsedScript;
			markDefinitelyShadowedCommands(script, shadowedCommands, argumentForwardingCommands);
			for (const error of script.errors ?? []) {
				errors.push(`${error.message} at offset ${error.pos}`);
			}
		}

		// Word parts are lazy and intentionally absent from Object.keys(). Reading
		// them is required to reach substitutions in words and expandable heredocs.
		if ("parts" in record && Array.isArray(record.parts)) visit(record.parts);
		for (const key of Object.keys(record)) {
			if (key !== "parts") visit(record[key]);
		}
	};

	try {
		visit(parse(command));
	} catch (error) {
		errors.push(error instanceof Error ? error.message : String(error));
	}

	return { segments, errors, hasDynamicExecutable: hasDynamic };
}

function matchesLeadingOption(option: string, knownSet: ReadonlySet<string>): boolean {
	if (knownSet.has(option)) return true;
	if (option.includes("=")) {
		const key = option.slice(0, option.indexOf("="));
		return knownSet.has(key);
	}
	return false;
}

function classifyLeadingOption(
	option: string,
	booleanOptions: ReadonlySet<string>,
	valueOptions: ReadonlySet<string>,
): OptionClassification {
	if (matchesLeadingOption(option, booleanOptions)) return "boolean";
	if (matchesLeadingOption(option, valueOptions)) return "value";
	return "unknown";
}

function parseSimpleCommands(command: string): ParsedCommands {
	const segments: ShellSegment[] = [];
	let words: string[] = [];
	let rawWords: string[] = [];
	let bareWords: string[] = [];
	let current = "";
	let currentRaw = "";
	let currentBare = "";
	let inSingle = false;
	let inDouble = false;
	let escapeNext = false;
	let skipNextWord = false;
	let inComment = false;

	const add = (ch: string, quoted: boolean): void => {
		current += ch;
		currentRaw += ch;
		if (!quoted) currentBare += ch;
	};

	const pushWord = () => {
		if (!current) {
			currentRaw = "";
			currentBare = "";
			return;
		}
		if (skipNextWord) {
			skipNextWord = false;
			current = "";
			currentRaw = "";
			currentBare = "";
			return;
		}
		words.push(current);
		rawWords.push(currentRaw);
		bareWords.push(currentBare);
		current = "";
		currentRaw = "";
		currentBare = "";
	};

	const pushSegment = () => {
		pushWord();
		if (words.length > 0) {
			segments.push({ words, rawWords, bare: bareWords.join(" ") });
			words = [];
			rawWords = [];
			bareWords = [];
		}
	};

	for (let i = 0; i < command.length; i += 1) {
		const ch = command[i];
		const next = command[i + 1];

		if (inComment) {
			if (ch === "\n") {
				inComment = false;
				if (skipNextWord) return { error: "Invalid redirection before comment" };
				pushSegment();
			}
			continue;
		}

		if (escapeNext) {
			add(ch, inDouble);
			escapeNext = false;
			continue;
		}

		if (inSingle) {
			if (ch === "'") {
				currentRaw += ch;
				inSingle = false;
			}
			else add(ch, true);
			continue;
		}

		if (inDouble) {
			if (ch === '"') {
				currentRaw += ch;
				inDouble = false;
				continue;
			}
			if (ch === "`") return { error: "Backtick command substitution is not supported" };
			if (ch === "$") {
				if (next === "(") return { error: "Command substitution is not supported" };
				add(ch, true);
				continue;
			}
			if (ch === "\\") {
				currentRaw += ch;
				if (next === "\n") {
					currentRaw += next;
					i += 1;
					continue;
				}
				if (next === "$" || next === "`" || next === '"' || next === "\\") {
					escapeNext = true;
				} else {
					current += ch;
				}
				continue;
			}
			add(ch, true);
			continue;
		}

		if (ch === "#" && current.length === 0) {
			inComment = true;
			continue;
		}

		if (ch === "\\") {
			currentRaw += ch;
			escapeNext = true;
			continue;
		}

		if (ch === "'") {
			currentRaw += ch;
			inSingle = true;
			continue;
		}

		if (ch === '"') {
			currentRaw += ch;
			inDouble = true;
			continue;
		}

		if (ch === "`") return { error: "Backtick command substitution is not supported" };
		if (ch === "$" && next === "(") return { error: "Command substitution is not supported" };

		if (ch === " " || ch === "\t" || ch === "\r") {
			pushWord();
			continue;
		}

		if (ch === "\n" || ch === ";") {
			if (skipNextWord) return { error: "Invalid redirection before command separator" };
			pushSegment();
			continue;
		}

		if (ch === "&") {
			if (next === "&") {
				if (skipNextWord) return { error: "Invalid redirection before command separator" };
				pushSegment();
				i += 1;
				continue;
			}
			return { error: "Background execution is not supported by the infra guard parser" };
		}

		if (ch === "|") {
			if (skipNextWord) return { error: "Invalid redirection before command separator" };
			pushSegment();
			if (next === "|" || next === "&") i += 1;
			continue;
		}

		if (ch === "<" || ch === ">") {
			if (next === "(") return { error: "Process substitution is not supported" };
			if (ch === "<" && next === "<") return { error: "Heredoc syntax is not supported" };
			if (/^\d+$/.test(current)) {
				current = "";
				currentRaw = "";
				currentBare = "";
			}
			else pushWord();
			if (next === ">" || next === "&" || next === "|") i += 1;
			skipNextWord = true;
			continue;
		}

		if (ch === "{" && next === "}") {
			add(ch, false);
			add(next, false);
			i += 1;
			continue;
		}

		if (ch === "(" || ch === ")" || ch === "{" || ch === "}") {
			return { error: `Unsupported shell grouping token: ${ch}` };
		}

		add(ch, false);
	}

	if (escapeNext) return { error: "Trailing escape is not supported" };
	if (inSingle || inDouble) return { error: "Unterminated quote" };
	if (skipNextWord && !current) return { error: "Redirection without a target is not supported" };

	pushSegment();
	return { segments };
}

function consumeKnownOptions(
	words: string[],
	startIndex: number,
	booleanOptions: ReadonlySet<string>,
	valueOptions: ReadonlySet<string>,
): ConsumedOptions {
	let index = startIndex;
	while (index < words.length) {
		const word = words[index];
		if (word === "--") return { index: index + 1 };
		if (!word.startsWith("-")) break;
		const classification = classifyLeadingOption(word, booleanOptions, valueOptions);
		if (classification === "unknown") {
			return { error: `Unsupported wrapper option: ${word}` };
		}
		if (classification === "boolean") {
			index += 1;
			continue;
		}
		if (word.includes("=")) {
			index += 1;
			continue;
		}
		if (index + 1 >= words.length) {
			return { error: `Missing value for option: ${word}` };
		}
		index += 2;
	}
	return { index };
}

function extractInvocation(words: string[]): InvocationResult {
	let index = 0;
	const wrappers: string[] = [];

	while (index < words.length) {
		while (index < words.length && isAssignmentWord(words[index])) index += 1;
		if (index >= words.length) {
			return { executable: null, args: [], words: [], wrappers };
		}

		const rawExecutable = words[index];
		const executable = stripPath(rawExecutable);

		if (executable === "toybox") {
			let appletIndex = index + 1;
			while (words[appletIndex] === "--long") appletIndex += 1;
			if (words[appletIndex] && !words[appletIndex].startsWith("-")) {
				wrappers.push(executable);
				index = appletIndex;
				continue;
			}
		}

		if (executable === "busybox" && words[index + 1] && !words[index + 1].startsWith("-")) {
			wrappers.push(executable);
			index += 1;
			continue;
		}

		if (executable === "env") {
			wrappers.push(executable);
			index += 1;
			const consumed = consumeKnownOptions(words, index, ENV_BOOLEAN_OPTIONS, ENV_VALUE_OPTIONS);
			if (consumed.error !== undefined) return { error: consumed.error };
			index = consumed.index;
			while (index < words.length && isAssignmentWord(words[index])) index += 1;
			continue;
		}

		if (executable === "sudo") {
			wrappers.push(executable);
			index += 1;
			const consumed = consumeKnownOptions(words, index, SUDO_BOOLEAN_OPTIONS, SUDO_VALUE_OPTIONS);
			if (consumed.error !== undefined) return { error: consumed.error };
			index = consumed.index;
			while (index < words.length && isAssignmentWord(words[index])) index += 1;
			continue;
		}

		if (executable === "time") {
			wrappers.push(executable);
			index += 1;
			const consumed = consumeKnownOptions(words, index, TIME_BOOLEAN_OPTIONS, TIME_VALUE_OPTIONS);
			if (consumed.error !== undefined) return { error: consumed.error };
			index = consumed.index;
			continue;
		}

		if (executable === "stdbuf") {
			wrappers.push(executable);
			index += 1;
			while (index < words.length && words[index].startsWith("-")) {
				const option = words[index];
				if (!(option.startsWith("-i") || option.startsWith("-o") || option.startsWith("-e"))) {
					return { error: `Unsupported stdbuf option: ${option}` };
				}
				index += 1;
			}
			continue;
		}

		if (executable === "nice") {
			wrappers.push(executable);
			index += 1;
			if (index < words.length && words[index].startsWith("-")) {
				const option = words[index];
				if (option === "-n" || option === "--adjustment") {
					if (index + 1 >= words.length) return { error: `Missing value for option: ${option}` };
					index += 2;
				} else if (/^-\d+$/.test(option)) {
					index += 1;
				} else {
					return { error: `Unsupported nice option: ${option}` };
				}
			}
			continue;
		}

		if (executable === "command" || executable === "builtin") {
			wrappers.push(executable);
			index += 1;
			while (index < words.length && words[index] === "--") index += 1;
			continue;
		}

		if (executable === "nohup" || executable === "chronic" || executable === "setsid") {
			wrappers.push(executable);
			index += 1;
			continue;
		}

		return {
			executable,
			rawExecutable,
			args: words.slice(index + 1),
			words: words.slice(index),
			wrappers,
		};
	}

	return { executable: null, args: [], words: [], wrappers };
}

function collectPositionals(
	words: string[],
	options: {
		maxPositionals: number;
		leadingBooleanOptions: ReadonlySet<string>;
		leadingValueOptions: ReadonlySet<string>;
	},
): CollectedPositionals {
	const { maxPositionals, leadingBooleanOptions, leadingValueOptions } = options;
	const positionals: string[] = [];
	let index = 0;

	while (index < words.length && positionals.length < maxPositionals) {
		const word = words[index];
		if (word === "--") {
			index += 1;
			while (index < words.length && positionals.length < maxPositionals) {
				positionals.push(words[index]);
				index += 1;
			}
			break;
		}

		if (word.startsWith("-")) {
			const classification = classifyLeadingOption(word, leadingBooleanOptions, leadingValueOptions);
			if (classification !== "unknown") {
				if (classification === "boolean") {
					index += 1;
					continue;
				}
				if (word.includes("=")) {
					index += 1;
					continue;
				}
				if (index + 1 >= words.length) {
					return { error: `Missing value for option: ${word}` };
				}
				index += 2;
				continue;
			}

			if (positionals.length === 0) {
				return { error: `Unsupported leading option: ${word}` };
			}

			if (word.includes("=")) {
				index += 1;
				continue;
			}

			if (index + 1 < words.length && !words[index + 1].startsWith("-")) {
				index += 2;
			} else {
				index += 1;
			}
			continue;
		}

		positionals.push(word);
		index += 1;
	}

	return { positionals };
}

function isInteractiveInterpreterCommand(command: string): boolean {
	const parsed = parseSimpleCommands(command);
	if ("error" in parsed || parsed.segments.length !== 1) return false;
	let invocation = extractInvocation(parsed.segments[0].words);
	if ("error" in invocation || !invocation.executable) return false;
	if (invocation.executable === "exec" && invocation.args.length > 0) {
		invocation = extractInvocation(invocation.args);
		if ("error" in invocation || !invocation.executable) return false;
	}
	return INTERACTIVE_INTERPRETERS.has(invocation.executable) || /^python(?:\d+(?:\.\d+)*)?$/.test(invocation.executable);
}

export {
	SHELL_RUNNERS,
	SHELL_CONTROL_KEYWORDS,
	SHELL_EXECUTION_BUILTINS,
	normalizeForInfraScan,
	containsGuardedText,
	hasDynamicExecutable,
	segmentsHaveDynamicExecutable,
	requiresAstRecovery,
	recoverAstCommands,
	parseSimpleCommands,
	extractInvocation,
	collectPositionals,
	isInteractiveInterpreterCommand,
};
export type { Invocation, InvocationResult, ParsedCommands, RecoveredCommands, ShellSegment };

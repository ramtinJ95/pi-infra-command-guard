import { GUARDED_EXECUTABLES } from "./guarded-executables.ts";

const GUARDED_PATTERN = new RegExp(`\\b(?:${GUARDED_EXECUTABLES.join("|")})\\b`, "i");

type ShellSegment = { words: string[]; bare: string };
type ParsedCommands =
	| { segments: ShellSegment[]; error?: undefined }
	| { segments?: undefined; error: string };
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

function containsGuardedText(text: string): boolean {
	return GUARDED_PATTERN.test(normalizeForInfraScan(text));
}

function hasDynamicExecutable(command: string): boolean {
	if (!String(command || "").includes("$")) return false;
	const parsed = parseSimpleCommands(command);
	if ("error" in parsed) return false;
	for (const segment of parsed.segments) {
		const invocation = extractInvocation(segment.words);
		if (!("error" in invocation) && invocation.executable?.includes("$")) return true;
	}
	return false;
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
	let bareWords: string[] = [];
	let current = "";
	let currentBare = "";
	let inSingle = false;
	let inDouble = false;
	let escapeNext = false;
	let skipNextWord = false;
	let inComment = false;

	const add = (ch: string, quoted: boolean): void => {
		current += ch;
		if (!quoted) currentBare += ch;
	};

	const pushWord = () => {
		if (!current) {
			currentBare = "";
			return;
		}
		if (skipNextWord) {
			skipNextWord = false;
			current = "";
			currentBare = "";
			return;
		}
		words.push(current);
		bareWords.push(currentBare);
		current = "";
		currentBare = "";
	};

	const pushSegment = () => {
		pushWord();
		if (words.length > 0) {
			segments.push({ words, bare: bareWords.join(" ") });
			words = [];
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
			if (ch === "'") inSingle = false;
			else add(ch, true);
			continue;
		}

		if (inDouble) {
			if (ch === '"') {
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
				escapeNext = true;
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
			escapeNext = true;
			continue;
		}

		if (ch === "'") {
			inSingle = true;
			continue;
		}

		if (ch === '"') {
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
				currentBare = "";
			}
			else pushWord();
			if (next === ">" || next === "&" || next === "|") i += 1;
			skipNextWord = true;
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
	parseSimpleCommands,
	extractInvocation,
	collectPositionals,
	isInteractiveInterpreterCommand,
};
export type { Invocation, InvocationResult, ParsedCommands, ShellSegment };

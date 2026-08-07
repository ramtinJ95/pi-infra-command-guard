import type {
	ExtensionAPI,
	ExtensionContext,
} from "@earendil-works/pi-coding-agent";

const PREFLIGHT_BROKER_REQUEST_CHANNEL =
	"@howaboua/pi-codex-conversion/code-mode-tool-preflight/request/v1";
const PREFLIGHT_BROKER_AVAILABLE_CHANNEL =
	"@howaboua/pi-codex-conversion/code-mode-tool-preflight/available/v1";

interface CodeModeToolCall {
	toolName: string;
	toolCallId: string;
	input: unknown;
	cwd: string;
	extensionContext?: ExtensionContext | undefined;
	signal: AbortSignal;
}

type CodeModeToolPreflightResult =
	| { block: true; reason: string }
	| undefined;

type CodeModeToolPreflight = (
	call: CodeModeToolCall,
) => CodeModeToolPreflightResult | Promise<CodeModeToolPreflightResult>;

interface CodeModeToolPreflightBroker {
	version: 1;
	isActive(): boolean;
	register(id: object, handler: CodeModeToolPreflight): () => void;
}

interface CodeModeToolPreflightRegistration {
	isAvailable(): boolean;
	unregister(): void;
}

function registerCodeModeToolPreflight(
	pi: ExtensionAPI,
	handler: CodeModeToolPreflight,
): CodeModeToolPreflightRegistration {
	const id = {};
	let active = true;
	let broker: CodeModeToolPreflightBroker | undefined;
	let unregisterFromBroker: (() => void) | undefined;

	const connect = (candidate: unknown) => {
		if (!active || !isCodeModeToolPreflightBroker(candidate)) return;
		if (candidate === broker && candidate.isActive()) return;
		unregisterFromBroker?.();
		broker = candidate;
		unregisterFromBroker = candidate.register(id, handler);
	};
	const stopListening = pi.events.on(
		PREFLIGHT_BROKER_AVAILABLE_CHANNEL,
		connect,
	);
	pi.events.emit(PREFLIGHT_BROKER_REQUEST_CHANNEL, { connect });

	const unregister = () => {
		if (!active) return;
		active = false;
		stopListening();
		unregisterFromBroker?.();
		unregisterFromBroker = undefined;
		broker = undefined;
	};
	pi.on("session_shutdown", unregister);
	return {
		isAvailable: () => active && Boolean(broker?.isActive()),
		unregister,
	};
}

function isCodeModeToolPreflightBroker(
	value: unknown,
): value is CodeModeToolPreflightBroker {
	return Boolean(
		value &&
			typeof value === "object" &&
			"version" in value &&
			value.version === 1 &&
			"isActive" in value &&
			typeof value.isActive === "function" &&
			"register" in value &&
			typeof value.register === "function",
	);
}

export {
	PREFLIGHT_BROKER_AVAILABLE_CHANNEL,
	PREFLIGHT_BROKER_REQUEST_CHANNEL,
	registerCodeModeToolPreflight,
};
export type {
	CodeModeToolCall,
	CodeModeToolPreflight,
	CodeModeToolPreflightBroker,
	CodeModeToolPreflightRegistration,
	CodeModeToolPreflightResult,
};

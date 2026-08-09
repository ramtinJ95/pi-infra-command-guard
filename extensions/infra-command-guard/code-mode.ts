import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type {
	CodeModeToolPreflight,
	CodeModeToolPreflightCall,
	CodeModeToolPreflightRegistration as UpstreamRegistration,
} from "@howaboua/pi-codex-conversion/code-mode-preflight";

interface CodeModeToolPreflightRegistration {
	isAvailable(): boolean;
	dispose(): void;
	readonly ready: Promise<void>;
}

function registerCodeModeToolPreflight(
	pi: ExtensionAPI,
	handler: CodeModeToolPreflight,
): CodeModeToolPreflightRegistration {
	let disposed = false;
	let upstream: UpstreamRegistration | undefined;
	const dispose = () => {
		if (disposed) return;
		disposed = true;
		upstream?.dispose();
		upstream = undefined;
	};
	const ready = import("@howaboua/pi-codex-conversion/code-mode-preflight")
		.then((module) => {
			if (!disposed) upstream = module.registerCodeModeToolPreflight(pi, handler);
		})
		.catch(() => undefined);
	pi.on("session_shutdown", dispose);
	return {
		isAvailable: () => !disposed && (upstream?.available ?? false),
		dispose,
		ready,
	};
}

export { registerCodeModeToolPreflight };
export type {
	CodeModeToolPreflight,
	CodeModeToolPreflightCall,
	CodeModeToolPreflightCall as CodeModeToolCall,
	CodeModeToolPreflightRegistration,
};

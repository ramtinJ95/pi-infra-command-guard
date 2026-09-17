import assert from "node:assert/strict";
import { requestInfraApproval, type ApprovalChoice } from "./approval-ui.ts";
import { test } from "./test-harness.ts";

function approvalContext(key: "b" | "n" | "y", duration: string | undefined) {
	return {
		ui: {
			async custom(factory: (...args: any[]) => { handleInput(data: string): void }) {
				let choice: ApprovalChoice = "cancel";
				const overlay = factory(
					{ requestRender() {} },
					{},
					{ matches: () => false },
					(selected: ApprovalChoice) => { choice = selected; },
				);
				overlay.handleInput(key);
				return choice;
			},
			async select() {
				return duration;
			},
		},
	} as never;
}

const DETAILS = {
	summary: "summary",
	flags: [],
	blastRadius: "blast radius",
};

test("approval overlay distinguishes one-time approval, bypass, and cancellation", async () => {
	let bypassSelections = 0;
	const bypass = {
		label: "Approve and bypass",
		async onSelect(select: (title: string, options: string[]) => Promise<string | undefined>) {
			bypassSelections += 1;
			return (await select("duration", ["10 minutes"])) === "10 minutes";
		},
	};
	assert.equal(
		await requestInfraApproval(approvalContext("y", undefined), DETAILS, "reason", "command", bypass),
		"once",
	);
	assert.equal(
		await requestInfraApproval(approvalContext("b", "10 minutes"), DETAILS, "reason", "command", bypass),
		"bypass",
	);
	assert.equal(
		await requestInfraApproval(approvalContext("b", undefined), DETAILS, "reason", "command", bypass),
		"cancel",
	);
	assert.equal(
		await requestInfraApproval(approvalContext("n", undefined), DETAILS, "reason", "command", bypass),
		"cancel",
	);
	assert.equal(bypassSelections, 2);
});

test("approval overlay renders an advisory in its own section after the guard reason", async () => {
	const theme = { fg: (_color: string, text: string) => text, bold: (text: string) => text, bg: (_color: string, text: string) => text };
	let rendered = "";
	const ctx = {
		ui: {
			async custom(factory: (...args: any[]) => { render(width: number): string[]; handleInput(data: string): void }) {
				let choice: ApprovalChoice = "cancel";
				const overlay = factory(
					{ requestRender() {}, terminal: { rows: 80 } },
					theme,
					{ matches: () => false },
					(selected: ApprovalChoice) => { choice = selected; },
				);
				rendered = overlay.render(140).join("\n");
				overlay.handleInput("n");
				return choice;
			},
			async select() { return undefined; },
		},
	} as never;
	const advisory = {
		heading: "TypeSafe review — experimental, advisory only",
		lines: [{ text: "Verdict: Mismatched — the reason may not describe this command", style: "warning" as const }],
	};
	assert.equal(await requestInfraApproval(ctx, DETAILS, "guard reason text", "rm target", undefined, advisory), "cancel");
	const reasonIndex = rendered.indexOf("Guard reason");
	const advisoryIndex = rendered.indexOf("TypeSafe review — experimental, advisory only");
	const summaryIndex = rendered.indexOf("What it does");
	assert.ok(reasonIndex >= 0 && advisoryIndex > reasonIndex && summaryIndex > advisoryIndex, rendered);
	assert.match(rendered, /Verdict: Mismatched/);

	rendered = "";
	await requestInfraApproval(ctx, DETAILS, "guard reason text", "rm target");
	assert.doesNotMatch(rendered, /TypeSafe/);

	// Advisory text may originate from a remote service: control sequences are
	// stripped and lines are bounded before rendering.
	const esc = String.fromCharCode(0x1b);
	const hostile = {
		heading: `TypeSafe review${esc}[2J heading`,
		lines: [
			{ text: `Verdict: ${esc}[31mSupported${esc}[0m${esc}]0;owned${String.fromCharCode(0x07)} Model: ${"m".repeat(2_000)}`, style: "text" as const },
		],
	};
	rendered = "";
	await requestInfraApproval(ctx, DETAILS, "guard reason text", "rm target", undefined, hostile);
	assert.doesNotMatch(rendered, new RegExp(esc));
	const flattened = rendered.replace(/[│╭╮╰╯─]/g, " ").replace(/\s+/g, " ");
	assert.match(flattened, /TypeSafe review heading/);
	assert.match(flattened, /Verdict: Supported Model: [m ]+…/);
	assert.ok(!flattened.replace(/ /g, "").includes("m".repeat(1_500)), "advisory lines are bounded");
});

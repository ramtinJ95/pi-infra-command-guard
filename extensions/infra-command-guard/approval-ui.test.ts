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

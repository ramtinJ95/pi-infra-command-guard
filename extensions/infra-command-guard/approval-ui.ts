import type { Theme } from "@earendil-works/pi-coding-agent";
import { Key, matchesKey, truncateToWidth, visibleWidth, wrapTextWithAnsi, type TUI } from "@earendil-works/pi-tui";

function wrapBlock(text: string, width: number): string[] {
	const normalized = String(text || "").replace(/\r\n/g, "\n");
	const wrapped = [];
	for (const rawLine of normalized.split("\n")) {
		if (rawLine.length === 0) {
			wrapped.push("");
			continue;
		}
		const lines = wrapTextWithAnsi(rawLine, Math.max(1, width));
		if (lines.length === 0) wrapped.push("");
		else wrapped.push(...lines);
	}
	return wrapped;
}

class InfraApprovalOverlay {
	private scrollOffset = 0;
	private viewHeight = 0;
	private totalLines = 0;
	private choiceIndex = 0;

	constructor(
		private tui: TUI,
		private theme: Theme,
		private keybindings: any,
		private approvalDetails: {
			summary: string;
			flags: Array<{ flag: string; meaning: string }>;
			blastRadius: string;
		},
		private reason: string,
		private command: string,
		private done: (approved: boolean) => void,
	) {}

	handleInput(data: string): void {
		if (this.keybindings.matches(data, "tui.select.cancel") || matchesKey(data, "n")) {
			this.done(false);
			return;
		}

		if (matchesKey(data, "y")) {
			this.done(true);
			return;
		}

		if (matchesKey(data, Key.up)) {
			this.scrollBy(-1);
			return;
		}

		if (matchesKey(data, Key.down)) {
			this.scrollBy(1);
			return;
		}

		if (matchesKey(data, "pageUp") || matchesKey(data, Key.ctrl("u"))) {
			this.scrollBy(-(this.viewHeight || 1));
			return;
		}

		if (matchesKey(data, "pageDown") || matchesKey(data, Key.ctrl("d"))) {
			this.scrollBy(this.viewHeight || 1);
			return;
		}

		if (matchesKey(data, Key.home) || matchesKey(data, "g")) {
			this.scrollTo(0);
			return;
		}

		if (matchesKey(data, Key.end) || matchesKey(data, Key.shift("g"))) {
			this.scrollTo(Number.MAX_SAFE_INTEGER);
			return;
		}

		if (
			this.keybindings.matches(data, "tui.select.down") ||
			matchesKey(data, "j") ||
			matchesKey(data, "l") ||
			matchesKey(data, Key.right) ||
			matchesKey(data, Key.tab)
		) {
			this.moveChoice(1);
			return;
		}

		if (
			this.keybindings.matches(data, "tui.select.up") ||
			matchesKey(data, "k") ||
			matchesKey(data, "h") ||
			matchesKey(data, Key.left) ||
			matchesKey(data, Key.shift("tab"))
		) {
			this.moveChoice(-1);
			return;
		}

		if (this.keybindings.matches(data, "tui.select.confirm")) {
			this.done(this.choiceIndex === 1);
		}
	}

	render(width: number): string[] {
		const border = (text: string) => this.theme.fg("border", text);
		const innerWidth = Math.max(40, width - 2);
		const bodyWidth = Math.max(10, innerWidth - 2);
		const maxHeight = Math.max(14, Math.floor((this.tui.terminal.rows || 24) * 0.85));
		const headerLines = 2;
		const footerLines = 4;
		const borderLines = 2;
		const contentHeight = Math.max(4, maxHeight - headerLines - footerLines - borderLines);
		const bodyLines = this.buildBodyLines(bodyWidth);
		this.totalLines = bodyLines.length;
		this.viewHeight = contentHeight;

		const maxScroll = Math.max(0, this.totalLines - contentHeight);
		this.scrollOffset = Math.max(0, Math.min(this.scrollOffset, maxScroll));
		const visibleBodyLines = bodyLines.slice(this.scrollOffset, this.scrollOffset + contentHeight);

		const lines: string[] = [];
		const padLine = (text: string) => {
			const truncated = truncateToWidth(text, innerWidth);
			return truncated + " ".repeat(Math.max(0, innerWidth - visibleWidth(truncated)));
		};

		const title = truncateToWidth(" Approve running this command? ", innerWidth);
		const titlePad = Math.max(0, innerWidth - visibleWidth(title));
		lines.push(border("╭") + this.theme.fg("accent", title) + border(`${"─".repeat(titlePad)}╮`));
		lines.push(border("│") + padLine(this.theme.fg("warning", " Review the explanation. Default selection is Cancel.")) + border("│"));

		for (const bodyLine of visibleBodyLines) {
			lines.push(border("│") + padLine(` ${bodyLine}`) + border("│"));
		}
		for (let i = visibleBodyLines.length; i < contentHeight; i += 1) {
			lines.push(border("│") + padLine("") + border("│"));
		}

		const start = this.totalLines === 0 ? 0 : Math.min(this.totalLines, this.scrollOffset + 1);
		const end = Math.min(this.totalLines, this.scrollOffset + this.viewHeight);
		const scrollText = this.totalLines > this.viewHeight
			? ` ${start}-${end}/${this.totalLines} • ↑↓ scroll • PgUp/PgDn or Ctrl+u/d page • g/G top/bottom`
			: " ↑↓ scroll • PgUp/PgDn or Ctrl+u/d page • g/G top/bottom";
		lines.push(border("│") + padLine(this.theme.fg("dim", scrollText)) + border("│"));
		lines.push(border("│") + padLine(this.renderChoiceLine(0, "Cancel", "warning")) + border("│"));
		lines.push(border("│") + padLine(this.renderChoiceLine(1, "Approve and run", "success")) + border("│"));
		lines.push(
			border("│") +
				padLine(this.theme.fg("dim", " j/k or h/l move choice • Enter confirm • y allow • n or Esc cancel")) +
				border("│"),
		);
		lines.push(border(`╰${"─".repeat(innerWidth)}╯`));

		return lines.map((line) => truncateToWidth(line, width));
	}

	invalidate(): void {}

	private buildBodyLines(width: number): string[] {
		const lines = [];
		lines.push(this.theme.fg("accent", this.theme.bold("Command")));
		for (const line of wrapBlock(this.command, Math.max(1, width - 2))) {
			lines.push(this.theme.fg("muted", "  ") + this.theme.fg("text", line));
		}
		lines.push("");
		lines.push(this.theme.fg("accent", this.theme.bold("Guard reason")));
		lines.push(...wrapBlock(this.reason, width).map((line) => this.theme.fg("warning", line)));
		lines.push("");
		lines.push(this.theme.fg("accent", this.theme.bold("What it does")));
		lines.push(...wrapBlock(this.approvalDetails.summary, width).map((line) => this.theme.fg("text", line)));
		lines.push("");
		lines.push(this.theme.fg("accent", this.theme.bold("Flags / options")));
		if (this.approvalDetails.flags.length === 0) {
			lines.push(this.theme.fg("muted", "No important flags or options."));
		} else {
			for (const item of this.approvalDetails.flags) {
				const label = this.theme.fg("muted", `• ${item.flag}: `);
				const wrapped = wrapBlock(item.meaning, Math.max(1, width - visibleWidth(`• ${item.flag}: `)));
				lines.push(label + this.theme.fg("text", wrapped[0] || ""));
				for (const continuation of wrapped.slice(1)) {
					lines.push(this.theme.fg("muted", "  ") + this.theme.fg("text", continuation));
				}
			}
		}
		lines.push("");
		lines.push(this.theme.fg("accent", this.theme.bold("Blast radius")));
		lines.push(...wrapBlock(this.approvalDetails.blastRadius, width).map((line) => this.theme.fg("text", line)));
		return lines;
	}

	private renderChoiceLine(index: number, label: string, color: "warning" | "success"): string {
		const selected = this.choiceIndex === index;
		const prefix = selected ? this.theme.fg("accent", "> ") : "  ";
		const text = selected ? this.theme.bg("selectedBg", this.theme.fg(color, ` ${label} `)) : this.theme.fg("dim", label);
		return `${prefix}${text}`;
	}

	private moveChoice(delta: number): void {
		this.choiceIndex = Math.max(0, Math.min(1, this.choiceIndex + (delta < 0 ? -1 : 1)));
		this.tui.requestRender();
	}

	private scrollBy(delta: number): void {
		const maxScroll = Math.max(0, this.totalLines - this.viewHeight);
		this.scrollOffset = Math.max(0, Math.min(this.scrollOffset + delta, maxScroll));
		this.tui.requestRender();
	}

	private scrollTo(target: number): void {
		const maxScroll = Math.max(0, this.totalLines - this.viewHeight);
		this.scrollOffset = Math.max(0, Math.min(target, maxScroll));
		this.tui.requestRender();
	}
}

async function requestInfraApproval(
	ctx: any,
	approvalDetails: { summary: string; flags: Array<{ flag: string; meaning: string }>; blastRadius: string },
	reason: string,
	command: string,
): Promise<boolean> {
	const approved = await ctx.ui.custom(
		(tui, theme, keybindings, done) => new InfraApprovalOverlay(tui, theme, keybindings, approvalDetails, reason, command, done),
		{
			overlay: true,
			overlayOptions: {
				anchor: "center",
				width: "82%",
				minWidth: 72,
				maxHeight: "85%",
			},
		},
	);
	return approved === true;
}

export { requestInfraApproval };

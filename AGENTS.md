# Agent guide

This repository is the canonical source for `@ramtinj95/pi-infra-command-guard`. Keep command policy, approval state, notification delivery, and Code Mode integration explainable and separately testable.

## User configuration

When a user asks to configure approval notifications or sound, edit:

```text
~/.pi/agent/infra-command-guard.json
```

Respect `PI_CODING_AGENT_DIR` when it is set; the file belongs at `infra-command-guard.json` inside that directory. Do not edit the copy under `~/.pi/agent/npm/node_modules` and do not configure notifications through the removed `PI_INFRA_COMMAND_GUARD_*` environment variables.

Use this shape:

```json
{
  "$schema": "https://raw.githubusercontent.com/ramtinJ95/pi-infra-command-guard/main/infra-command-guard.schema.json",
  "notifications": {
    "enabled": true,
    "backend": "auto"
  },
  "integrations": {
    "herdr": {
      "enabled": true
    }
  },
  "sound": {
    "enabled": false,
    "path": null
  }
}
```

Notification backends:

- `auto`: use native notifications on macOS and Windows; on Linux, use a recognized terminal notifier first and otherwise fall back to `notify-send`
- `terminal`: require Kitty OSC 99 or Ghostty OSC 9; warn in Pi when neither is detected
- `native`: use macOS Notification Center through `osascript`, Linux `notify-send`, or a Windows notification balloon

Herdr panes do not pass raw terminal notification sequences to the outer terminal. `integrations.herdr.enabled` defaults to `true`; inside a Herdr pane, `auto` uses native delivery and explicit `terminal` calls `herdr notification show`. Herdr's own `[ui.toast].delivery` must allow the broker request. Herdr currently reuses one Kitty notification identifier, so repeated terminal notifications can update without a fresh banner; recommend `auto` or `native` for reliable attention. Do not mutate Herdr's configuration automatically.

Sound is independent of notification delivery. Set `sound.enabled` to `true` and `sound.path` to a user-owned audio file. `~` is expanded, and relative paths resolve from the directory containing the JSON file. The package ships no sound files.

Configuration is read for every approval request, so changes apply to the next popup without `/reload`. Invalid JSON, unknown fields, unsupported values, and enabled sound without a path produce a visible Pi warning and disable attention mechanisms for that request; they never change command approval behavior.

After editing the file, have the user run `/infra-guard-notify-test`. Terminal protocols cannot confirm that the OS displayed an accepted notification; if Kitty, Ghostty, or the OS suppresses it, configure `native` instead.

## Development

### Architecture

`extensions/infra-command-guard/index.ts` is composition only. Keep dependencies directed toward it; internal modules must not import `index.ts`.

- `attention.ts`: JSON configuration, native and terminal notifications, Herdr routing, and custom sound
- `shell.ts`: shell parsing, wrapper extraction, and indirect-execution detection
- `tool-policies.ts`: kubectl, Terraform, Helm, and Argo CD allowlists and evaluators
- `policy.ts`: guarded-command orchestration and stable policy exports
- `approvals.ts`: execution identity, expiring one-time grants, and guard decisions
- `approval-ui.ts`: structured approval overlay
- `code-mode.ts`: private Code Mode runtime adapter and reload-safe bridge symbols
- `index.ts`: Pi hooks, tools, commands, and lifecycle composition

Keep tool-specific policy out of `shell.ts`. Add or change infrastructure command rules in `tool-policies.ts`, then compose them through `policy.ts`. Global `Symbol.for(...)` keys are reload compatibility boundaries and must remain byte-for-byte stable.

### Checks

- Run `npm run check` after changes; it type-checks, tests, and verifies the package contents.
- Preserve the block → structured TUI approval → exact one-time retry flow.
- Notification failures must never approve, execute, or suppress a blocked command.
- Keep terminal protocols explicit: Kitty uses OSC 99; Ghostty uses OSC 9. Do not send guessed control sequences to unknown terminals.
- Keep the extension silent by default and do not bundle third-party audio.

Read `README.md` for policy scope, installation, limitations, and release compatibility.

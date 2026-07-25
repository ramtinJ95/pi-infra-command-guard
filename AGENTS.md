# Agent guide

This repository is the canonical source for `@ramtinj95/pi-infra-command-guard`. Keep command policy, approval state, notification delivery, and Code Mode integration explainable and separately testable.

## User configuration

When a user asks to configure command guards, approval notifications, or sound, edit:

```text
~/.pi/agent/infra-command-guard.json
```

Respect `PI_CODING_AGENT_DIR` when it is set; the file belongs at `infra-command-guard.json` inside that directory. Do not edit the copy under `~/.pi/agent/npm/node_modules` and do not configure notifications through the removed `PI_INFRA_COMMAND_GUARD_*` environment variables.

Use this shape:

```json
{
  "$schema": "https://raw.githubusercontent.com/ramtinJ95/pi-infra-command-guard/main/infra-command-guard.schema.json",
  "guards": {
    "kubectl": true,
    "terraform": true,
    "helm": true,
    "argocd": true,
    "aws": true,
    "az": true,
    "gcloud": true,
    "docker": true,
    "git": true,
    "vault": true,
    "find": true,
    "rm": true,
    "rmdir": true,
    "rsync": true,
    "shred": true,
    "truncate": true,
    "unlink": true
  },
  "commands": {
    "terraform": {
      "allow": [],
      "requireApproval": []
    }
  },
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

All guard keys default to `true`; users may specify only overrides. Available keys are `kubectl`, `terraform`, `helm`, `argocd`, `aws`, `az`, `gcloud`, `docker`, `git`, `vault`, `find`, `rm`, `rmdir`, `rsync`, `shred`, `truncate`, and `unlink`. Disabled guards bypass checks for that executable while enabled guards in mixed commands remain enforced. If every guard is disabled, dynamic executable and interactive-session restrictions are also bypassed because no guarded target remains.

The Docker policy is targeted rather than fail-closed: it guards resource removal/pruning, destructive Compose flags, arbitrary container execution, privileged or host-control options, Docker control-plane and registry changes, and mutations aimed at an explicit CLI host/context. Ordinary diagnostics and development workflows remain allowed, as do unknown `docker` subcommands without a recognized risk. It classifies `docker compose`; the standalone `docker-compose` executable is conservatively approval-required as indirect Docker invocation. It cannot infer endpoints from inherited environment/current-context state or inspect Dockerfiles and Compose files.

The Git policy is also targeted. It guards destructive clean/reset/restore/checkout forms, forced branch and tag deletion, stash/reflog destruction, forced worktree removal, immediate object pruning, and destructive pushes. Ordinary Git commands and unknown subcommands remain allowed. Invocation-local aliases are non-bypassable because they hide behavior; inherited aliases, hooks, helpers, and repository-dependent checkout ambiguity remain outside lexical classification.

The Vault policy is strict: only help, version, status, and common command-specific help forms are allowed by default. Reads, lists, unwraps, KV operations, authentication/token/policy/operator commands, agent/server processes, and unknown commands require approval because they can reveal secrets or change security-critical state. Environment-selected endpoints/tokens and server-side mount/plugin behavior remain outside lexical classification.

The local-file policies require approval for `rm`, mutations through `unlink`, `rmdir`, `shred`, and `truncate`, `find -delete`, and rsync deletion/removal flags. Ordinary `find` searches and `rsync` transfers remain allowed, as do rsync dry runs. Rsync options that can supply executable commands remain non-bypassable when they contain shell behavior or another guarded tool. Keep these as individual guard keys so users can disable or customize one tool without weakening the others.

`commands.<cli>.allow` bypasses built-in policy for matching commands, while `requireApproval` forces approval and takes precedence. Rules are case-sensitive normalized token prefixes, omit the executable, and support `*` within a token. Paths, recognized wrappers, and known non-command global CLI options do not affect matching; command-like help/version options remain matchable. Prefix allow rules include every unmatched trailing argument, must contain at least one literal character, and cannot bypass `kubectl --raw`, `gcloud --flags-file`, Helm post-renderer, or invocation-local Git alias restrictions. The CLI guard toggle is the master switch: when false, command overrides for that CLI are ignored. Shell-level ambiguity restrictions remain outside command overrides. Changing guard settings or command rules invalidates pending requests and unused approvals. Invalid configuration fails safe with every guard enabled, no custom overrides, and a visible Pi warning.

When translating a user request into configuration:

- Read and preserve the existing file; change only the requested fields.
- Use `guards.<cli>: false` for “never guard this CLI.” Do not emulate that with a broad allow rule.
- Add a rule to `allow` for “let this command run without approval.” Explain that a prefix also covers trailing arguments and flags when the requested rule is broad or safety-sensitive.
- Add a rule to `requireApproval` for “always ask before this command.” A wildcard-only rule such as `"*"` is valid here and forces approval for every non-empty command under that enabled CLI.
- Omit the executable from rules. For example, use `"output"`, not `"terraform output"`; use `"delete pod dev-*"`, not `"kubectl delete pod dev-*"`.
- Keep resource-specific allow rules as narrow as practical. Prefer `"delete pod dev-*"` over `"delete"` when that reflects the request.
- If `allow` and `requireApproval` both match, tell the user that `requireApproval` wins.
- If `guards.<cli>` is `false`, tell the user that command rules for that CLI are retained in JSON but inactive until the guard is enabled again.
- Do not add empty sections or expand omitted defaults unless the user asks for a complete example.

Common mappings:

```json
{
  "guards": {
    "az": false
  },
  "commands": {
    "terraform": {
      "allow": ["output"]
    },
    "kubectl": {
      "requireApproval": ["logs"]
    },
    "aws": {
      "requireApproval": ["*"]
    }
  }
}
```

This means: never inspect Azure CLI commands, allow Terraform output without approval, always require approval for kubectl logs, and require approval for every AWS command. Unspecified lists are empty and unspecified guards remain enabled.

Notification backends:

- `auto`: use native notifications on macOS and Windows; on Linux, use a recognized terminal notifier first and otherwise fall back to `notify-send`
- `terminal`: require Kitty OSC 99 or Ghostty OSC 9; warn in Pi when neither is detected
- `native`: use macOS Notification Center through `osascript`, Linux `notify-send`, or a Windows notification balloon

Herdr panes do not pass raw terminal notification sequences to the outer terminal. `integrations.herdr.enabled` defaults to `true`; inside a Herdr pane, `auto` uses native delivery and explicit `terminal` calls `herdr notification show`. Herdr's own `[ui.toast].delivery` must allow the broker request. Herdr currently reuses one Kitty notification identifier, so repeated terminal notifications can update without a fresh banner; recommend `auto` or `native` for reliable attention. Do not mutate Herdr's configuration automatically.

Sound is independent of notification delivery. Set `sound.enabled` to `true` and `sound.path` to a user-owned audio file. `~` is expanded, and relative paths resolve from the directory containing the JSON file. The package ships no sound files.

Configuration is read for every shell command and approval request, so changes apply without `/reload`. Invalid JSON, unknown fields, unsupported values, and enabled sound without a path produce a visible Pi warning, keep every command guard enabled, and disable attention mechanisms for that request.

After editing the file, have the user run `/infra-guard-notify-test`. Terminal protocols cannot confirm that the OS displayed an accepted notification; if Kitty, Ghostty, or the OS suppresses it, configure `native` instead.

## Development

### Architecture

`extensions/infra-command-guard/index.ts` is composition only. Keep dependencies directed toward it; internal modules must not import `index.ts`.

- `attention.ts`: JSON configuration, native and terminal notifications, Herdr routing, and custom sound
- `shell.ts`: shell parsing, wrapper extraction, and indirect-execution detection
- `tool-policies.ts`: tool allowlists, evaluators, global-option normalization, and non-bypassable tool risks
- `policy.ts`: guarded-command orchestration, custom command-rule matching, and stable policy exports
- `approvals.ts`: execution identity, expiring one-time grants, and guard decisions
- `approval-ui.ts`: structured approval overlay
- `code-mode.ts`: private Code Mode runtime adapter and reload-safe bridge symbols
- `guarded-executables.ts`: canonical guarded executable names shared by scanning and policy dispatch
- `index.ts`: Pi hooks, tools, commands, and lifecycle composition

Keep tool-specific policy out of `shell.ts`. Add an executable name in `guarded-executables.ts`, implement its rules in `tool-policies.ts`, and register its evaluator in `policy.ts`; the typed registry fails type-checking when a guarded executable has no evaluator. Global `Symbol.for(...)` keys are reload compatibility boundaries and must remain byte-for-byte stable.

Tests mirror module ownership (`attention.test.ts`, `shell.test.ts`, `policy.test.ts`, `command-policy-corpus.test.ts`, `approvals.test.ts`, and `code-mode.test.ts`). Keep cross-module Pi lifecycle coverage in `extension.test.ts`. `index.test.ts` is only the aggregate runner; do not restore a production `_test` export to reach internals. Shell fuzzing must be deterministic so CI failures are reproducible.

### Checks

- Run `npm run check` after changes; it type-checks, tests, and verifies the package contents.
- Preserve the block → structured TUI approval → exact one-time retry flow.
- Notification failures must never approve, execute, or suppress a blocked command.
- Keep terminal protocols explicit: Kitty uses OSC 99; Ghostty uses OSC 9. Do not send guessed control sequences to unknown terminals.
- Keep the extension silent by default and do not bundle third-party audio.

Read `README.md` for policy scope, installation, limitations, and release compatibility.

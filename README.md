# infra-command-guard

Global pi extension that wraps the built-in `bash` tool and intercepts direct and GPT-5.6 Code Mode `exec_command` calls, asking for approval before running higher-risk `kubectl`, `terraform`, `helm`, `argocd`, and `rm` commands.

## Install

```bash
pi install npm:@ramtinj95/pi-infra-command-guard
```

Then run `/reload` or restart Pi. Pi packages execute with full system access; review this extension before installation.

## Goals

- Keep normal `bash` behavior and rendering for allowed commands
- Guard the `exec_command` developer tool used by API-style Pi sessions
- Guard nested `tools.exec_command(...)` calls after Code Mode resolves their runtime arguments
- Fail closed at the outer Code Mode `exec` call if its nested provider cannot be guarded
- Add a fast in-process guard before execution
- Fail closed outside TUI mode
- Stay separate from Claude hooks
- Allow `kubectl port-forward`, including common wrapped/backgrounded forms
- Mirror the Claude hook flow: block first, have the model call an approval tool with a plain-language explanation, then allow one exact execution-context retry only if approved

## What it auto-allows

### kubectl
Low-risk diagnostics and read-style commands, including:

- `get`
- `describe`
- `logs` / `log`
- `top`
- `explain`
- `api-resources`
- `api-versions`
- `version`
- `wait`
- `diff`
- `port-forward`
- wrapped/backgrounded `kubectl port-forward` commands when the command's kubectl usage is limited to port-forward
- `auth can-i`
- `auth whoami`
- `rollout status`
- `rollout history`

### terraform
Low-risk planning and inspection commands, including:

- `fmt`
- `validate`
- `version`
- `graph`
- `providers`
- `init`
- `plan`
- `show`
- `state list`
- `state show`
- `workspace list`
- `workspace show`
- `workspace select`

### helm

Explicitly low-risk operations including:

- `version`, `env`, and `help`
- `list`, `status`, and `history`
- `search`, `show`, `template`, `lint`, and `verify`
- `repo list`, `plugin list`, and `dependency list`

`helm get` remains guarded because stored release values and manifests can expose secrets. Commands using `--post-renderer` remain guarded because they execute an external program.

### argocd

Explicitly low-risk operations including:

- `version`, `help`, and `completion`
- `app list`, `get`, `history`, `logs`, `resources`, and `wait`
- `app actions list`
- `cluster list|get`
- `repo list|get`
- `proj list|get`
- `account list|get|can-i`
- `cert list` and `gpg list`

`argocd app diff` and `app manifests` remain guarded because rendered output can expose secret material.

## What requires approval

- Mutating infra commands such as `kubectl delete`, `terraform apply`, `helm upgrade`, and `argocd app sync`
- `rm` commands
- Wrapped or path-qualified `rm` commands such as `sudo rm`, `env rm`, and `/bin/rm`
- Executables resolved through shell variables, such as `$TOOL ...`
- Assignment-based indirection such as `K=kubectl; $K ...`
- Commands the guard cannot classify safely
- Indirect shell-runner patterns such as `bash -lc "kubectl ..."` or `xargs kubectl ...`, except for commands whose kubectl usage is limited to `port-forward`
- Some sensitive read paths, e.g. `kubectl get secret ...`

## Approval flow

1. The wrapped `bash` tool or direct/nested `exec_command` preflight blocks the command and returns a pending approval request identifier to the model.
2. The model must call `approve_infra_command` with:
   - the pending approval request identifier
   - the exact blocked command
   - the guard reason
   - a structured summary of what the command does
   - important flags/options and what they change
   - the concrete blast radius
3. Pi opens a scrollable overlay with one consistent layout: command, guard reason, summary, flags/options, blast radius, then `Cancel` / `Approve and run`.
4. If approved, the extension records a one-time approval for that exact execution context.
5. The model retries the exact same shell call; the guard consumes the approval and runs it.

Approvals expire after ten minutes. If the command, working directory, requested shell, TTY mode, login mode, or tool path changes, the retry is blocked again.

The request identifier is required. Missing, expired, or mismatched request identifiers are rejected; the blocked command must be rerun to create a fresh request.

## Code Mode integration

The current integration wraps Code Mode's in-process nested `exec_command` provider. The wrapper resolves dynamic JavaScript before applying the guard, so commands assembled at runtime are covered without parsing the outer JavaScript source.

This adapter uses `pi-codex-conversion` internals until that package exposes a supported nested-tool preflight API. The guard installs the wrapper at session/turn startup and verifies it again before every outer `exec` or `wait`. If an update changes those internals, the outer Code Mode call is blocked with a compatibility error instead of silently running unguarded.

The current package is validated with Pi 0.81.1 and `@howaboua/pi-codex-conversion` 2.2.16. Normal Pi `bash` guarding does not require Code Mode. Because the Code Mode adapter intentionally fails closed around private internals, test the guard after upgrading either package.

## Approval notifications and sound

The package is silent by default and ships no audio files. Configure attention mechanisms in `~/.pi/agent/infra-command-guard.json`:

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

When `PI_CODING_AGENT_DIR` overrides Pi's configuration directory, put `infra-command-guard.json` there instead. The extension reads the file for every approval request, so edits apply to the next popup without `/reload`.

### Notification backends

- `auto` (recommended): use native notifications on macOS and Windows; on Linux, prefer a recognized terminal notifier and fall back to `notify-send`
- `terminal`: require Kitty OSC 99 or Ghostty OSC 9; unknown terminals produce a visible Pi warning
- `native`: use Notification Center through `osascript` on macOS, `notify-send` on Linux, or a notification balloon on Windows

Kitty notifications explicitly request silent delivery so custom sound remains separately controlled. Other terminal emulators and desktop notification services can still apply user-level notification policies.

Terminal protocols cannot confirm that the OS displayed a notification after accepting the control sequence. Use `/infra-guard-notify-test` after configuring the extension. If terminal delivery is blocked by terminal or OS permissions, select `native` instead.

### Herdr integration

Herdr panes terminate application escape sequences inside Herdr's emulated terminal; raw Kitty or Ghostty notification sequences do not reach the outer terminal. When `integrations.herdr.enabled` is `true` (the default) and `HERDR_ENV=1`, `auto` uses native OS delivery instead of emitting unusable terminal sequences. Explicit `terminal` uses Herdr's notification broker:

```toml
[ui.toast]
delivery = "terminal"
```

That setting belongs in Herdr's configuration. Herdr can also be configured for `system`, `herdr`, or `off`; infra-command-guard does not override it. Explicit `terminal` reports failure if Herdr does not show the request. Herdr currently reuses one Kitty notification identifier, so later terminal notifications can update an existing notification without showing a fresh banner. Use `auto` or `native` when reliable attention matters. Set `integrations.herdr.enabled` to `false` to disable all Herdr-specific routing.

### Custom sound

To play a user-supplied sound independently of the notification backend:

```json
{
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
    "enabled": true,
    "path": "sounds/infra-approval.wav"
  }
}
```

`~` is expanded. Relative paths resolve from the directory containing `infra-command-guard.json`. The extension uses `afplay` on macOS, tries `paplay` then `aplay` on Linux, and supports WAV through PowerShell on Windows.

Invalid JSON, unknown fields, unsupported backend values, and enabled sound without a path produce a Pi warning and disable attention mechanisms for that request. Notification and sound failures never authorize or execute the blocked command.

Version 0.2.0 replaces the 0.1.x `PI_INFRA_COMMAND_GUARD_SOUND_PATH` and `PI_INFRA_COMMAND_GUARD_NATIVE_NOTIFICATION` environment variables with this JSON file.

## Notes

- This guards the LLM `bash` tool override, not user `!command` shell usage.
- Interactive shell/interpreter sessions requested with `tty=true` are denied rather than approvable because later `write_stdin` input cannot be classified reliably. Run complete non-interactive commands instead.
- Code Mode TOML custom tools execute their configured programs directly and are trusted capabilities outside this `exec_command` guard.
- This is an in-process policy guard, not an OS sandbox. It cannot know that an inherited alias, shell function, opaque script, or custom executable eventually invokes guarded tooling when the command contains no guarded name or dynamic executable position. Kubernetes RBAC, scoped Terraform credentials, and filesystem permissions remain the hard security boundary.
- Interactive approval uses a custom scrollable overlay instead of pi's default confirm popup.
  - `↑` / `↓` scroll
  - `PgUp` / `PgDn` or `Ctrl+u` / `Ctrl+d` page
  - `g` / `G` jump to top/bottom
  - `j` / `k` move between `Cancel` and `Approve and run`
- The model supplies structured fields rather than a markdown blob, so the UI avoids repeating command/reason/blast-radius text.
- Because it overrides the built-in `bash` tool, pi may show the standard override warning in interactive mode.
- No notification setting is required; notifications and sound are opt-in.

## Reload

Run:

```bash
/reload
```

or restart pi.

## Tests

From the repository root:

```bash
npm install
npm test
npm run test:package
```

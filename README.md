# infra-command-guard

Global pi extension that wraps the built-in `bash` tool and intercepts direct and GPT-5.6 Code Mode `exec_command` calls, asking for approval before higher-risk infrastructure, cloud, and destructive local-file commands.

> [!WARNING]
> Setting `guardUnclassifiedCommands` to `false` opts into a less conservative mode: commands run without approval when the extension cannot positively classify them as dangerous. This can allow dangerous behavior hidden by unsupported shell syntax, variables, shell runners, unknown CLI operations, or unread external inputs. The extension is not a sandbox; operating-system and service permissions remain the hard security boundary.

```json
{
  "guardUnclassifiedCommands": false
}
```

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

### AWS CLI

Read-style service operations such as `describe-*`, `get-*`, `list-*`, `head-*`, `search-*`, `scan`, `query`, and waiters are allowed. Explicit diagnostics and content reads include CloudWatch Logs filtering/tailing, S3 Select, RDS log download, Route 53 DNS tests, and CloudFormation cost estimation. Sensitive exceptions remain guarded, including Secrets Manager reads, SSM parameter-value retrieval, credential/token retrieval, and STS operations other than `get-caller-identity`. Unknown operations require approval by default and are allowed in classified-dangerous-only mode unless their action is recognized as a mutation.

### Azure CLI

Stable commands with explicit read-style actions such as `list`, `show`, `get-*`, `exists`, `query`, diagnostics/tests, log tailing, patch assessment, `status`, `validate`, `wait`, and deployment `what-if` are allowed. Secret, credential, key-value, connection-string, and app-setting reads remain guarded. Mutating actions remain guarded; unknown actions require approval by default.

### Google Cloud CLI

Stable commands with explicit read-style actions such as `list`, `describe`, `get-*`, `read`, `search-*`, logs, storage `cat`/`du`/`hash`, IAM policy troubleshooting, `status`, and operation waits are allowed. Authentication-token output, credential retrieval, Secret Manager reads, and recognized mutations remain guarded. `alpha`, `beta`, `--flags-file`, and unknown commands require approval by default.

### Docker

Docker uses a targeted high-risk policy rather than a strict command allowlist. Normal diagnostics and common local workflows remain allowed, including listing, logs, inspect, build, pull, ordinary run/start/stop, and `docker compose up` or `down` without data-removal flags.

Approval is required for resource removal and pruning; `docker compose rm`; Compose volume/image/orphan removal; `exec`, `debug`, and Compose `exec`/`run`; privileged containers; high-impact capabilities, devices, host namespaces, host-root or Docker-socket mounts, and insecure build entitlements; Swarm and control-plane changes; registry writes and credential changes; and mutations directed through explicit `--context`/`-c` or `--host`/`-H` options. Read-only commands against an explicit endpoint remain allowed. Documented Compose dry runs remain allowed for removal previews.

The policy classifies the current `docker compose` subcommand. The deprecated standalone `docker-compose` executable has no command-level classifier and is conservatively approval-required as indirect Docker invocation. Unknown `docker` subcommands are allowed unless they contain a recognized risk. The guard cannot see a Docker endpoint selected through inherited environment variables or the current saved context, and it does not inspect Dockerfiles or Compose files for privileged behavior.

### Git

Git also uses a targeted destructive-operation policy. Ordinary status, diff, history, staging, commits, rebase/merge, normal branch switching, `git rm`, staged-only restore, recoverable reset modes, and normal pushes remain allowed.

Approval is required for `git clean` except dry-run; `reset --hard`; working-tree restore and unambiguous checkout path replacement; forced/discarding checkout or switch; forced branch deletion and tag deletion; stash drop/clear; reflog deletion/expiration; forced dirty-worktree removal; immediate object pruning; and force, force-with-lease, mirror, deletion, or destructive-refspec pushes. Valid dry-run forms remain allowed. Invocation-local aliases supplied through `-c alias.*` or `--config-env=alias.*` remain guarded even when a custom `allow` rule matches because they can hide arbitrary behavior.

Unknown Git subcommands are allowed. The guard does not read repository or user configuration, so inherited aliases, hooks, remote helpers, external `git-*` commands, and checkout forms whose branch/path meaning depends on repository state remain outside command-level classification.

### Vault

Vault uses a strict low-risk allowlist by default because reads can return secrets and mutations can change authentication or control-plane state. Bare help, help topics, version, status, and common command-specific help forms are allowed. Known sensitive Vault families remain guarded in both modes; unknown commands are allowed only in classified-dangerous-only mode.

Guarded operations include `read`, `list`, `unwrap`, KV reads and writes, generic write/delete, login and token operations, auth methods, secrets engines, policies, operator lifecycle commands, and agent/server processes. Unknown commands require approval only in the default conservative mode. Narrow `commands.vault.allow` rules can deliberately permit a trusted path or operation after global server/namespace options are normalized.

The guard classifies argv only. Vault policies, response wrapping, namespaces, mount behavior, environment-provided addresses/tokens, and server-side plugin behavior remain outside the lexical policy.

### Local file tools

Ordinary `find` searches and `rsync` transfers without deletion flags are allowed. `rsync --dry-run` and `rsync -n` remain allowed even when showing what a deletion-enabled transfer would do. Executable-bearing rsync options remain guarded when they contain shell behavior or delegate to another guarded tool. Help/version-only invocations of `unlink`, `rmdir`, `shred`, and `truncate` are also allowed.

## What requires approval

- Mutating infra commands such as `kubectl delete`, `terraform apply`, `helm upgrade`, `argocd app sync`, `aws ec2 terminate-instances`, `az vm delete`, and `gcloud compute instances delete`
- Higher-risk Docker commands such as `docker volume rm`, `docker system prune`, `docker exec`, `docker run --privileged`, and `docker --context production compose up`
- Destructive Git commands such as `git clean -fdx`, `git reset --hard`, `git stash clear`, and `git push --force`
- Vault secret access and mutations such as `vault read secret/production`, `vault kv get`, `vault write`, and `vault operator seal`
- `rm` commands
- Wrapped or path-qualified `rm` commands such as `sudo rm`, `env rm`, and `/bin/rm`
- `unlink`, `rmdir`, `shred`, and `truncate` mutations
- `find -delete`
- `rsync --delete`, its timing/exclusion variants, `--delete-missing-args`, and `--remove-source-files` unless dry-run mode is active
- Executables resolved through shell variables, such as `$TOOL ...`, by default
- Assignment-based indirection such as `K=kubectl; $K ...`, by default
- Commands the guard cannot classify safely, by default
- Indirect shell-runner patterns such as `bash -lc "kubectl ..."` or `xargs kubectl ...`, by default, except for commands whose kubectl usage is limited to `port-forward`
- Some sensitive read paths, e.g. Kubernetes secrets, cloud secret values, credentials, tokens, keys, and connection strings

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

## Temporary pauses and scoped bypasses

Two session-scoped escape hatches exist for focused work. Both live in memory only: they never persist to disk and never survive a `/reload`, an extension reload, or a Pi restart.

### Pausing the guard

Run `/infra-guard` and choose `Pause guard…`, then pick 10 minutes, 30 minutes, or 1 hour. While paused, every guarded command runs without approval except interactive TTY shell/interpreter sessions, which stay blocked because their later input cannot be classified. The same menu shows the remaining time, resumes the guard early, and clears everything. Active pauses and bypasses are also shown in the Pi status line.

### Scoped bypasses from the approval overlay

When a blocked command contains a single guarded invocation whose prefix identifies a target — for example `kubectl --kubeconfig ~/.config/staging/kubeconfig delete pod foo` — the approval overlay gains a third choice, `Approve & bypass … for…`. Picking a duration (10 minutes, 30 minutes, or 1 hour) approves the command and records a bypass rule for that session:

- the rule is the invocation's normalized token prefix, including path-valued options such as `--kubeconfig` (with `~` expanded), so the target environment is part of the rule
- trailing arguments are covered: bypassing the prefix above also covers `kubectl --kubeconfig ~/.config/staging/kubeconfig delete pod bar`
- the rule only applies while the command runs in the blocked command's working directory or a subdirectory
- commands the static policy already allows are never offered, and non-bypassable risks (`kubectl --raw`, `gcloud --flags-file`, Helm `--post-renderer`, invocation-local Git aliases) can never be bypassed
- unparseable commands produce no bypass offer

Bypass rules apply uniformly to the `bash` tool, direct `exec_command` calls, and Code Mode nested calls.

> [!WARNING]
> Pauses and bypasses deliberately weaken the guard. A pause exposes every guarded tool, and a scoped bypass still covers every trailing argument under its prefix — including other resources in the same cluster or namespace. Prefer the narrowest prefix and shortest duration that covers the task.

## Code Mode integration

The integration registers an awaited nested-tool preflight through Pi's public cross-extension event bus. Code Mode resolves the JavaScript tool name and input first, then runs the guard before invoking `exec_command`, so commands assembled at runtime are covered without parsing the outer JavaScript source.

The guard verifies that a compatible preflight broker is connected before every outer `exec` or `wait`. If Code Mode is absent or too old to expose the supported API, the outer call is blocked instead of silently running unguarded. Other nested Code Mode tools pass through unchanged.

This integration is validated with Pi 0.84.1 and requires a `@howaboua/pi-codex-conversion` release containing the Code Mode nested-tool preflight API. Normal Pi `bash` and structured `exec_command` guarding do not require Code Mode.

## Configuration

Configure the extension in `~/.pi/agent/infra-command-guard.json`. When `PI_CODING_AGENT_DIR` overrides Pi's configuration directory, put `infra-command-guard.json` there instead. The extension reads the file for every shell command and approval request, so edits apply immediately without `/reload`.

### Classified-dangerous-only mode

`guardUnclassifiedCommands` defaults to `true`, preserving conservative behavior for omitted and existing configurations. Set it to `false` only when you accept that classification gaps can bypass approval:

```json
{
  "guardUnclassifiedCommands": false
}
```

With `false`, uncertainty alone is allowed: unsupported shell or wrapper syntax, dynamic executable variables, opaque shell runners, unknown CLI operations, unsupported global-option layouts, indirect guarded names used as search data, and unread inputs such as `gcloud --flags-file`. Positively recognized mutations, sensitive reads, destructive local-file operations, and arbitrary-execution or raw-control capabilities remain guarded—for example `rm`, `kubectl delete`, `vault read`, `terraform apply`, Docker privileged/exec forms, Helm post-renderers, invocation-local Git aliases, and `kubectl --raw`.

Matching `commands.<cli>.requireApproval` rules still require approval. Custom `allow` rules and guard toggles retain their documented precedence. Interactive TTY shell/interpreter sessions and incompatible Code Mode execution channels remain blocked because those channels cannot be guarded at all. Invalid configuration restores the conservative `true` default with every guard enabled and shows a Pi warning.

### Guard toggles

Every guard is enabled by default. Add only the overrides you need:

```json
{
  "$schema": "https://raw.githubusercontent.com/ramtinJ95/pi-infra-command-guard/main/infra-command-guard.schema.json",
  "guards": {
    "terraform": false,
    "az": false,
    "rm": false
  }
}
```

Available keys are `kubectl`, `terraform`, `helm`, `argocd`, `aws`, `az`, `gcloud`, `docker`, `git`, `vault`, `rm`, `unlink`, `rmdir`, `shred`, `truncate`, `find`, and `rsync`. A disabled guard bypasses policy checks for direct, path-qualified, and recognized wrapper invocations such as `sudo` and `env`. Enabled guards in the same command remain enforced. Dynamic executable expressions and opaque shell-runner commands require approval while any guard is enabled unless classified-dangerous-only mode is selected.

Changing guard settings invalidates pending requests and unused one-time approvals. Run the command again under the new configuration if approval is still required.

Existing configuration files without `guards` retain the current behavior with every guard enabled. Invalid configuration fails safe: every command guard remains enabled and Pi displays a warning.

### Command overrides

Enabled guards can customize individual commands:

```json
{
  "commands": {
    "terraform": {
      "allow": ["output"],
      "requireApproval": ["plan -destroy"]
    },
    "kubectl": {
      "allow": ["delete pod dev-*"],
      "requireApproval": ["logs"]
    }
  }
}
```

- `allow` bypasses the built-in policy for a matching command. This can permit mutations, sensitive output, and any unmatched trailing command flags, so keep rules narrow. An allow rule must contain at least one literal character; use the CLI's master toggle instead of an all-wildcard rule.
- `requireApproval` forces approval even when the built-in policy would allow the command.
- `requireApproval` wins if both lists match.
- `guards.<cli>: false` is the master switch and ignores all command overrides for that CLI.

Rules omit the executable and match case-sensitive normalized argument prefixes. Executable paths and recognized wrappers such as `sudo` and `env` are ignored. Known non-command global CLI options are removed wherever they occur before matching, while command-specific flags, arguments, and command-like `--help`/`--version` options retain their order. `*` matches characters within one token and never crosses whitespace. For example, `delete pod dev-*` matches `sudo kubectl --context production delete pod dev-api --wait=false`, but not `kubectl delete pod production-api`. Because rules are prefixes, every trailing argument is also covered by the match; use `requireApproval` for narrower exceptions that must remain guarded.

Overrides apply only after the shell invocation has been parsed. They do not bypass interactive-session, rsync executable-option, `kubectl --raw`, Helm post-renderer, or invocation-local Git alias restrictions. Dynamic executable, opaque shell-runner, unsupported shell syntax, and `gcloud --flags-file` uncertainty remains non-bypassable by an `allow` rule but is allowed when `guardUnclassifiedCommands` is `false`. Changing command rules also invalidates pending requests and unused approvals. Invalid rules are ignored together with the rest of the invalid configuration, leaving every guard enabled under its built-in policy.

### Approval notifications and sound

The package is silent by default and ships no audio files. Configure attention mechanisms in `~/.pi/agent/infra-command-guard.json`:

```json
{
  "$schema": "https://raw.githubusercontent.com/ramtinJ95/pi-infra-command-guard/main/infra-command-guard.schema.json",
  "guards": {
    "terraform": false,
    "az": false
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

Invalid JSON, unknown fields, malformed command rules, non-boolean guard values, unsupported backend values, and enabled sound without a path produce a Pi warning. Invalid configuration keeps every command guard enabled under its built-in policy and disables attention mechanisms for that request. Notification and sound failures never authorize or execute the blocked command.

Version 0.2.0 replaces the 0.1.x `PI_INFRA_COMMAND_GUARD_SOUND_PATH` and `PI_INFRA_COMMAND_GUARD_NATIVE_NOTIFICATION` environment variables with this JSON file.

## Notes

- This guards the LLM `bash` tool override, not user `!command` shell usage.
- Interactive shell/interpreter sessions requested with `tty=true` are denied rather than approvable because later `write_stdin` input cannot be classified reliably. Run complete non-interactive commands instead.
- Code Mode TOML custom tools execute their configured programs directly and are trusted capabilities outside this `exec_command` guard.
- This is an in-process policy guard, not an OS sandbox. It cannot know that an inherited alias, shell function, opaque script, or custom executable eventually invokes guarded tooling when the command contains no guarded name or dynamic executable position. Kubernetes RBAC, scoped Terraform credentials, and filesystem permissions remain the hard security boundary.
- Docker daemon access remains a hard security boundary. The targeted Docker policy cannot infer the active daemon from inherited `DOCKER_HOST`/`DOCKER_CONTEXT` state or detect privileged behavior encoded inside Dockerfiles and Compose files.
- Git remote permissions, protected branches, and backups remain hard boundaries. The targeted Git policy cannot resolve inherited aliases, hooks, helpers, or repository-dependent branch/path ambiguity.
- Vault ACLs, scoped tokens, response wrapping, and server audit devices remain hard boundaries. The strict Vault policy cannot infer environment-selected servers or server-side mount/plugin behavior.
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
npm run benchmark:policy
```

The cloud and command policy corpora cover hundreds of documented read, mutation, sensitive-read, authentication, local-configuration, container, and destructive-file decisions. Decisions are exercised through path-qualified executables, wrappers, global-option placements, shell composition, pipelines, and simple executable obfuscation.

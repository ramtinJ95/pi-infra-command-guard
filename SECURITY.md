# Security

This extension is a guardrail, not a security sandbox. Keep Kubernetes RBAC, cloud credentials, Terraform credentials, Docker daemon access, Git remote permissions, Vault ACLs/tokens, and filesystem permissions scoped independently of this package.

The opt-in `guardUnclassifiedCommands: false` mode deliberately fails open when shell or CLI behavior cannot be classified. Unsupported syntax, executable variables, opaque runners, unknown operations, and unread external inputs can therefore conceal dangerous behavior from the guard. Positively classified risks remain guarded, but operating-system and service permissions—not this extension—must be the security boundary.

Report suspected bypasses through GitHub's private vulnerability reporting for this repository. Do not include live credentials, kubeconfigs, Terraform state, or production command output in a report.

const GUARDED_EXECUTABLES = ["kubectl", "terraform", "helm", "argocd", "rm"] as const;

type GuardedExecutable = (typeof GUARDED_EXECUTABLES)[number];

export { GUARDED_EXECUTABLES };
export type { GuardedExecutable };

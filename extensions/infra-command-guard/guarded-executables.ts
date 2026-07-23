const GUARDED_EXECUTABLES = ["kubectl", "terraform", "helm", "argocd", "az", "aws", "gcloud", "rm"] as const;

type GuardedExecutable = (typeof GUARDED_EXECUTABLES)[number];
type GuardSettings = Readonly<Record<GuardedExecutable, boolean>>;

const DEFAULT_GUARD_SETTINGS = {
	argocd: true,
	aws: true,
	az: true,
	gcloud: true,
	helm: true,
	kubectl: true,
	rm: true,
	terraform: true,
} satisfies GuardSettings;

function enabledGuardedExecutables(settings: GuardSettings): GuardedExecutable[] {
	return GUARDED_EXECUTABLES.filter((executable) => settings[executable]);
}

function hasEnabledGuards(settings: GuardSettings): boolean {
	return GUARDED_EXECUTABLES.some((executable) => settings[executable]);
}

export { GUARDED_EXECUTABLES, DEFAULT_GUARD_SETTINGS, enabledGuardedExecutables, hasEnabledGuards };
export type { GuardedExecutable, GuardSettings };

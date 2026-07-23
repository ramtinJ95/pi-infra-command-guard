const GUARDED_EXECUTABLES = ["kubectl", "terraform", "helm", "argocd", "az", "aws", "gcloud", "rm"] as const;

type GuardedExecutable = (typeof GUARDED_EXECUTABLES)[number];
type GuardSettings = Readonly<Record<GuardedExecutable, boolean>>;
type CommandOverrideRules = Readonly<{ allow: readonly string[]; requireApproval: readonly string[] }>;
type CommandOverrides = Readonly<Record<GuardedExecutable, CommandOverrideRules>>;

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

const DEFAULT_COMMAND_OVERRIDES = {
	argocd: { allow: [], requireApproval: [] },
	aws: { allow: [], requireApproval: [] },
	az: { allow: [], requireApproval: [] },
	gcloud: { allow: [], requireApproval: [] },
	helm: { allow: [], requireApproval: [] },
	kubectl: { allow: [], requireApproval: [] },
	rm: { allow: [], requireApproval: [] },
	terraform: { allow: [], requireApproval: [] },
} satisfies CommandOverrides;

function enabledGuardedExecutables(settings: GuardSettings): GuardedExecutable[] {
	return GUARDED_EXECUTABLES.filter((executable) => settings[executable]);
}

function hasEnabledGuards(settings: GuardSettings): boolean {
	return GUARDED_EXECUTABLES.some((executable) => settings[executable]);
}

export {
	GUARDED_EXECUTABLES,
	DEFAULT_GUARD_SETTINGS,
	DEFAULT_COMMAND_OVERRIDES,
	enabledGuardedExecutables,
	hasEnabledGuards,
};
export type { CommandOverrideRules, CommandOverrides, GuardedExecutable, GuardSettings };

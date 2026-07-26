const GUARDED_EXECUTABLES = [
	"kubectl",
	"terraform",
	"helm",
	"argocd",
	"az",
	"aws",
	"gcloud",
	"docker",
	"git",
	"vault",
	"find",
	"rmdir",
	"rm",
	"rsync",
	"shred",
	"truncate",
	"unlink",
] as const;

type GuardedExecutable = (typeof GUARDED_EXECUTABLES)[number];
type GuardSettings = Readonly<Record<GuardedExecutable, boolean>>;
type CommandOverrideRules = Readonly<{ allow: readonly string[]; requireApproval: readonly string[] }>;
type CommandOverrides = Readonly<Record<GuardedExecutable, CommandOverrideRules>>;
type CommandPolicySettings = Readonly<{
	guardUnclassifiedCommands: boolean;
	guards: GuardSettings;
	commands: CommandOverrides;
}>;

const DEFAULT_GUARD_SETTINGS = {
	argocd: true,
	aws: true,
	az: true,
	docker: true,
	find: true,
	gcloud: true,
	git: true,
	helm: true,
	kubectl: true,
	rm: true,
	rmdir: true,
	rsync: true,
	shred: true,
	terraform: true,
	truncate: true,
	unlink: true,
	vault: true,
} satisfies GuardSettings;

const DEFAULT_COMMAND_OVERRIDES = {
	argocd: { allow: [], requireApproval: [] },
	aws: { allow: [], requireApproval: [] },
	az: { allow: [], requireApproval: [] },
	docker: { allow: [], requireApproval: [] },
	find: { allow: [], requireApproval: [] },
	gcloud: { allow: [], requireApproval: [] },
	git: { allow: [], requireApproval: [] },
	helm: { allow: [], requireApproval: [] },
	kubectl: { allow: [], requireApproval: [] },
	rm: { allow: [], requireApproval: [] },
	rmdir: { allow: [], requireApproval: [] },
	rsync: { allow: [], requireApproval: [] },
	shred: { allow: [], requireApproval: [] },
	terraform: { allow: [], requireApproval: [] },
	truncate: { allow: [], requireApproval: [] },
	unlink: { allow: [], requireApproval: [] },
	vault: { allow: [], requireApproval: [] },
} satisfies CommandOverrides;

const DEFAULT_COMMAND_POLICY_SETTINGS = {
	guardUnclassifiedCommands: true,
	guards: DEFAULT_GUARD_SETTINGS,
	commands: DEFAULT_COMMAND_OVERRIDES,
} satisfies CommandPolicySettings;

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
	DEFAULT_COMMAND_POLICY_SETTINGS,
	enabledGuardedExecutables,
	hasEnabledGuards,
};
export type { CommandOverrideRules, CommandOverrides, CommandPolicySettings, GuardedExecutable, GuardSettings };

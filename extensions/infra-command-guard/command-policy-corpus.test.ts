import assert from "node:assert/strict";
import { evaluateCommand } from "./policy.ts";
import { test } from "./test-harness.ts";

const DOCKER_ALLOWED = [
	"docker",
	"docker --help",
	"docker version",
	"docker info",
	"docker ps",
	"docker images",
	"docker inspect api",
	"docker logs api",
	"docker stats --no-stream",
	"docker image ls",
	"docker image inspect api:latest",
	"docker volume ls",
	"docker volume inspect database",
	"docker network ls",
	"docker network inspect app",
	"docker system df",
	"docker context ls",
	"docker node ls",
	"docker service ls",
	"docker stack ps app",
	"docker secret inspect api-key",
	"docker plugin inspect example/plugin",
	"docker builder ls",
	"docker buildx du",
	"docker build .",
	"docker pull nginx:latest",
	"docker run --name api nginx:latest",
	"docker run -v ./src:/app nginx:latest",
	"docker run --privileged=false nginx:latest",
	"docker stop api",
	"docker compose up -d",
	"docker compose down",
	"docker compose down --volumes=false --remove-orphans=false",
	"docker compose ps",
	"docker compose logs api",
	"docker compose config",
	"docker compose --dry-run down -v",
	"docker compose --dry-run rm -f",
	"docker --context production compose --dry-run down -v",
	"docker -H tcp://daemon.example:2375 ps",
	"docker -Htcp://daemon.example:2375 info",
	"docker --context production inspect api",
	"docker -cproduction service ls",
	"docker --debug compose -p api ps",
	"docker future-command --future-flag",
];

const DOCKER_APPROVALS = [
	"docker rm api",
	"docker rmi api:latest",
	"docker container rm api",
	"docker image remove api:latest",
	"docker volume rm database",
	"docker network rm app",
	"docker container prune -f",
	"docker image prune -a",
	"docker volume prune -a",
	"docker network prune -f",
	"docker system prune --volumes",
	"docker builder prune -a",
	"docker builder rm local-builder",
	"docker buildx prune -a",
	"docker buildx rm remote-builder",
	"docker compose rm -f api",
	"docker compose down -v",
	"docker compose down --volumes",
	"docker compose down --rmi all",
	"docker compose down --remove-orphans",
	"docker exec api sh -c 'rm -rf /data'",
	"docker container exec api sh",
	"docker debug api",
	"docker compose exec api sh",
	"docker compose run api migrate",
	"docker run --privileged nginx:latest",
	"docker run --privileged=true nginx:latest",
	"docker run --cap-add SYS_ADMIN nginx:latest",
	"docker run --device /dev/sda nginx:latest",
	"docker run --network host nginx:latest",
	"docker run --pid=host nginx:latest",
	"docker run -v /:/host nginx:latest",
	"docker run -v/var/run/docker.sock:/var/run/docker.sock nginx:latest",
	"docker run --mount type=bind,src=/,dst=/host nginx:latest",
	"docker run --mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock nginx:latest",
	"docker run --security-opt seccomp=unconfined nginx:latest",
	"docker buildx build --allow=security.insecure .",
	"docker swarm init",
	"docker swarm join-token worker",
	"docker node rm worker-1",
	"docker node update --availability drain worker-1",
	"docker service update api",
	"docker service rm api",
	"docker stack deploy -c compose.yaml api",
	"docker stack rm api",
	"docker secret create api-key secret.txt",
	"docker secret rm api-key",
	"docker config create proxy nginx.conf",
	"docker plugin install example/plugin",
	"docker context use production",
	"docker context create production --docker host=ssh://example",
	"docker context export production",
	"docker login registry.example.com",
	"docker logout registry.example.com",
	"docker push registry.example.com/api:latest",
	"docker image push registry.example.com/api:latest",
	"docker manifest push registry.example.com/api:latest",
	"docker build --push .",
	"docker buildx build --push .",
	"docker buildx imagetools create registry.example.com/api:latest",
	"docker compose build --push",
	"docker compose push",
	"docker -H tcp://daemon.example:2375 run nginx:latest",
	"docker -Htcp://daemon.example:2375 stop api",
	"docker --context production compose up -d",
	"docker -cproduction restart api",
	"docker --future-global-option run nginx:latest",
];

const GIT_ALLOWED = [
	"git",
	"git --version",
	"git help reset",
	"git -C repository status",
	"git -Crepository status",
	"git -c color.ui=false status",
	"git -ccolor.ui=false status",
	"git --git-dir=.git status",
	"git status --short",
	"git diff",
	"git log --oneline",
	"git show HEAD",
	"git add file.txt",
	"git commit -m update",
	"git commit --amend --no-edit",
	"git rebase main",
	"git merge feature",
	"git cherry-pick HEAD~1",
	"git revert HEAD",
	"git rm tracked.txt",
	"git mv old.txt new.txt",
	"git clean -n",
	"git clean -ndx",
	"git clean -ne keep.me",
	"git clean --dry-run -d",
	"git reset",
	"git reset --mixed HEAD~1",
	"git reset --soft HEAD~1",
	"git restore --staged file.txt",
	"git restore -S file.txt",
	"git restore --staged=true --worktree=false file.txt",
	"git checkout main",
	"git checkout ambiguous-name",
	"git switch main",
	"git branch -d merged-feature",
	"git tag --list",
	"git stash list",
	"git stash pop",
	"git reflog show",
	"git worktree list",
	"git gc",
	"git gc --prune=2.weeks.ago",
	"git prune -n",
	"git prune --dry-run",
	"git push origin main",
	"git push --dry-run --force origin main",
	"git push -n origin :main",
	"git push origin main:refs/heads/main",
	"git custom-helper --custom-option",
];

const GIT_APPROVALS = [
	"git clean",
	"git clean -f",
	"git clean -fdx",
	"git clean -i",
	"git clean --dry-run --no-dry-run -f",
	"git clean -e --dry-run -f",
	"git reset --hard",
	"git reset --hard HEAD~1",
	"git restore file.txt",
	"git restore --worktree file.txt",
	"git restore --staged --worktree file.txt",
	"git restore -SW file.txt",
	"git checkout -- file.txt",
	"git checkout HEAD~1 -- file.txt",
	"git checkout -f main",
	"git checkout -qf main",
	"git switch --discard-changes main",
	"git switch --force main",
	"git branch -D feature",
	"git branch -df feature",
	"git branch --delete --force feature",
	"git tag -d release-1",
	"git tag --delete release-1",
	"git stash drop stash@{0}",
	"git stash clear",
	"git reflog expire --expire=now --all",
	"git reflog delete HEAD@{1}",
	"git worktree remove --force ../dirty-tree",
	"git worktree remove -f ../dirty-tree",
	"git gc --prune=now",
	"git gc --prune now",
	"git prune",
	"git prune --expire=now",
	"git prune --dry-run --no-dry-run",
	"git prune --expire --dry-run",
	"git push --force origin main",
	"git push --dry-run --no-dry-run --force origin main",
	"git push --push-option --dry-run --force origin main",
	"git push -f origin main",
	"git push --force-with-lease origin main",
	"git push --force-with-lease=main origin main",
	"git push --force-if-includes --force-with-lease origin main",
	"git push --mirror origin",
	"git push --delete origin feature",
	"git push -d origin feature",
	"git push origin +main",
	"git push origin +main:main",
	"git push origin :feature",
	"git push --repo=origin +main",
	"git push --signed origin +main",
	"git -c alias.deploy='!dangerous-command' deploy",
	"git -calias.deploy='!dangerous-command' deploy",
	"git -c color.ui=false -c alias.deploy='!dangerous-command' deploy",
	"git --config-env=alias.deploy=DEPLOY_ALIAS deploy",
	"git --future-global-option status",
];

const VAULT_ALLOWED = [
	"vault",
	"vault -h",
	"vault -help",
	"vault --help",
	"vault -version",
	"vault --version",
	"vault help",
	"vault help read",
	"vault version",
	"vault status",
	"vault status -format=json",
	"vault status -address=https://vault.example.com",
	"vault -address=https://vault.example.com status",
	"vault -address https://vault.example.com status",
	"vault -namespace=team status",
	"vault status -tls-skip-verify",
	"vault read -help",
	"vault read --help",
	"vault kv get -help",
	"vault operator -help",
];

const VAULT_APPROVALS = [
	"vault read secret/production",
	"vault -address=https://vault.example.com read secret/production",
	"vault list secret/metadata",
	"vault unwrap wrapped-token",
	"vault kv get secret/production",
	"vault kv list secret/",
	"vault write secret/production password=value",
	"vault write secret/production value=-help",
	"vault kv get -mount -help secret/production",
	"vault delete secret/production",
	"vault kv put secret/production password=value",
	"vault kv patch secret/production password=value",
	"vault kv delete secret/production",
	"vault kv destroy -versions=1 secret/production",
	"vault kv undelete -versions=1 secret/production",
	"vault kv metadata delete secret/production",
	"vault kv rollback -version=1 secret/production",
	"vault login token=value",
	"vault token create -policy=deploy",
	"vault token revoke token-value",
	"vault token renew token-value",
	"vault token lookup",
	"vault auth list",
	"vault auth enable userpass",
	"vault auth disable userpass",
	"vault secrets list",
	"vault secrets enable kv-v2",
	"vault secrets disable secret/",
	"vault policy list",
	"vault policy read deploy",
	"vault policy write deploy policy.hcl",
	"vault policy delete deploy",
	"vault operator init",
	"vault operator unseal unseal-key",
	"vault operator seal",
	"vault operator rekey",
	"vault operator rotate",
	"vault operator generate-root",
	"vault operator step-down",
	"vault operator raft snapshot restore backup.snap",
	"vault agent -config=agent.hcl",
	"vault server -config=server.hcl",
	"vault ssh user@host",
	"vault lease revoke database/creds/app/id",
	"vault audit enable file file_path=audit.log",
	"vault plugin register secret example-plugin",
	"vault namespace list",
	"vault monitor",
	"vault future-command --future-option",
	"vault -future-global-option status",
];

function replaceExecutable(command: string, current: string, replacement: string): string {
	return command.replace(new RegExp(`^${current}`), replacement);
}

function variants(executable: "docker" | "git" | "vault", command: string): string[] {
	const midpoint = Math.max(1, Math.floor(executable.length / 2));
	const obfuscated = `${executable.slice(0, midpoint)}"${executable.slice(midpoint)}"`;
	return [
		command,
		replaceExecutable(command, executable, `/usr/local/bin/${executable}`),
		replaceExecutable(command, executable, obfuscated),
		`env CORPUS_TEST=1 ${command}`,
		`sudo -n ${command}`,
		`command ${command}`,
		`printf ready && ${command}`,
		`${command} | cat`,
	];
}

test(`Docker policy corpus: ${DOCKER_ALLOWED.length + DOCKER_APPROVALS.length} decisions`, () => {
	assert.ok(DOCKER_ALLOWED.length >= 30);
	assert.ok(DOCKER_APPROVALS.length >= 50);
	for (const command of DOCKER_ALLOWED) {
		for (const variant of variants("docker", command)) {
			assert.equal(evaluateCommand(variant).allow, true, `unexpected approval: ${variant}`);
		}
	}
	for (const command of DOCKER_APPROVALS) {
		for (const variant of variants("docker", command)) {
			assert.equal(evaluateCommand(variant).allow, false, `unexpected allow: ${variant}`);
		}
	}
});

test(`Git policy corpus: ${GIT_ALLOWED.length + GIT_APPROVALS.length} decisions`, () => {
	assert.ok(GIT_ALLOWED.length >= 40);
	assert.ok(GIT_APPROVALS.length >= 40);
	for (const command of GIT_ALLOWED) {
		for (const variant of variants("git", command)) {
			assert.equal(evaluateCommand(variant).allow, true, `unexpected approval: ${variant}`);
		}
	}
	for (const command of GIT_APPROVALS) {
		for (const variant of variants("git", command)) {
			assert.equal(evaluateCommand(variant).allow, false, `unexpected allow: ${variant}`);
		}
	}
});

test(`Vault policy corpus: ${VAULT_ALLOWED.length + VAULT_APPROVALS.length} decisions`, () => {
	assert.ok(VAULT_ALLOWED.length >= 15);
	assert.ok(VAULT_APPROVALS.length >= 40);
	for (const command of VAULT_ALLOWED) {
		for (const variant of variants("vault", command)) {
			assert.equal(evaluateCommand(variant).allow, true, `unexpected approval: ${variant}`);
		}
	}
	for (const command of VAULT_APPROVALS) {
		for (const variant of variants("vault", command)) {
			assert.equal(evaluateCommand(variant).allow, false, `unexpected allow: ${variant}`);
		}
	}
});

test("standalone docker-compose is conservatively guarded as literal indirect Docker execution", () => {
	for (const command of ["docker-compose ps", "/usr/local/bin/docker-compose down -v", "sudo -n docker-compose up -d"]) {
		assert.equal(evaluateCommand(command).allow, false, command);
	}
});

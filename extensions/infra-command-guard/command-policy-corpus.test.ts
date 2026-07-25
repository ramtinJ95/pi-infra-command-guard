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

function replaceExecutable(command: string, executable: string): string {
	return command.replace(/^docker/, executable);
}

function variants(command: string): string[] {
	return [
		command,
		replaceExecutable(command, "/usr/local/bin/docker"),
		replaceExecutable(command, 'do"cker"'),
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
		for (const variant of variants(command)) {
			assert.equal(evaluateCommand(variant).allow, true, `unexpected approval: ${variant}`);
		}
	}
	for (const command of DOCKER_APPROVALS) {
		for (const variant of variants(command)) {
			assert.equal(evaluateCommand(variant).allow, false, `unexpected allow: ${variant}`);
		}
	}
});

test("standalone docker-compose is conservatively guarded as literal indirect Docker execution", () => {
	for (const command of ["docker-compose ps", "/usr/local/bin/docker-compose down -v", "sudo -n docker-compose up -d"]) {
		assert.equal(evaluateCommand(command).allow, false, command);
	}
});

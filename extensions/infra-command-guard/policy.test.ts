import assert from "node:assert/strict";
import { evaluateCommand } from "./policy.ts";
import { test } from "./test-harness.ts";

test("rm classification covers executable paths and common wrappers", () => {
	for (const command of [
		"rm -rf target",
		"/bin/rm -rf target",
		"sudo rm -rf target",
		"env FOO=bar rm -rf target",
		"command rm -rf target",
		"xargs rm",
		"find . -exec rm {} ;",
	]) {
		assert.equal(evaluateCommand(command).allow, false, command);
	}

	assert.equal(evaluateCommand('printf "%s\\n" "rm"').allow, true);
	assert.equal(evaluateCommand("kubectl port-forward service/api 8080:80 && rm marker").allow, false);
});

test("kubectl and terraform retain their safe and approval-required behavior", () => {
	for (const command of [
		"kubectl get pods",
		"/usr/local/bin/kubectl --context prod get pods",
		"sudo -n kubectl -n production describe deployment/api",
		"kubectl logs deployment/api",
		"kubectl port-forward service/api 8080:80",
		"nohup kubectl port-forward service/api 8080:80 >port-forward.log 2>&1 &",
		"kubectl auth can-i get pods",
		"terraform plan",
		"terraform -chdir=infra plan",
		"env TF_IN_AUTOMATION=1 terraform show plan.out",
		"terraform state list",
		"terraform workspace show",
	]) {
		assert.equal(evaluateCommand(command).allow, true, command);
	}

	for (const command of [
		"kubectl delete pod api",
		"/usr/local/bin/kubectl --context prod apply -f deployment.yaml",
		"env KUBECONFIG=cluster.yaml kubectl patch deployment api -p {}",
		"kubectl get secrets",
		"kubectl describe secret/api-token",
		"kubectl --raw=/api/v1/namespaces/default/secrets",
		"kubectl rollout restart deployment/api",
		"terraform apply",
		"sudo terraform -chdir infra apply plan.out",
		"terraform destroy",
		"terraform output",
		'bash -lc "kubectl get pods"',
		'python -c "import os; os.system(\'terraform apply\')"',
	]) {
		assert.equal(evaluateCommand(command).allow, false, command);
	}
});

test("helm allows explicit reads and guards mutations or sensitive output", () => {
	for (const command of [
		"helm version --short",
		"helm --kube-context prod list --all-namespaces",
		"helm -n production status api",
		"helm history api",
		"helm search repo ingress",
		"helm show values ./chart",
		"helm template api ./chart",
		"helm lint ./chart",
		"helm repo list",
		"helm plugin list",
		"helm dependency list ./chart",
		"helm help uninstall",
	]) {
		assert.equal(evaluateCommand(command).allow, true, command);
	}

	for (const command of [
		"helm install api ./chart",
		"helm upgrade api ./chart",
		"helm uninstall api",
		"helm rollback api 2",
		"helm test api",
		"helm get values api",
		"helm repo add internal https://charts.example.com",
		"helm repo update",
		"helm plugin install https://example.com/plugin.git",
		"helm registry login registry.example.com",
		"helm push chart.tgz oci://registry.example.com/charts",
		"helm template api ./chart --post-renderer ./renderer",
		"helm diff upgrade api ./chart",
		"sudo /opt/homebrew/bin/helm upgrade api ./chart",
	]) {
		assert.equal(evaluateCommand(command).allow, false, command);
	}
});

test("argocd allows explicit reads and guards application or control-plane mutations", () => {
	for (const command of [
		"argocd version --client",
		"argocd --server argocd.example.com app list",
		"argocd app get api",
		"argocd app history api",
		"argocd app logs api",
		"argocd app resources api",
		"argocd app wait api --health",
		"argocd app actions list api",
		"argocd cluster list",
		"argocd cluster get production",
		"argocd repo list",
		"argocd repo get https://github.com/example/repo.git",
		"argocd proj list",
		"argocd account can-i sync applications '*'",
		"argocd cert list --cert-type https",
		"argocd gpg list",
	]) {
		assert.equal(evaluateCommand(command).allow, true, command);
	}

	for (const command of [
		"argocd app create api --repo https://github.com/example/repo.git",
		"argocd app sync api",
		"argocd app rollback api 2",
		"argocd app delete api",
		"argocd app set api --revision main",
		"argocd app terminate-op api",
		"argocd app patch-resource api --kind Deployment",
		"argocd app actions run restart --kind Deployment api",
		"argocd app diff api",
		"argocd app manifests api",
		"argocd cluster add production",
		"argocd cluster rm production",
		"argocd repo add https://github.com/example/repo.git",
		"argocd proj create production",
		"argocd account generate-token",
		"argocd admin cluster kubeconfig production",
		"argocd login argocd.example.com",
		"env ARGOCD_OPTS=--grpc-web /usr/local/bin/argocd app sync api",
	]) {
		assert.equal(evaluateCommand(command).allow, false, command);
	}
});

test("guarded commands fail closed through shell composition and obfuscation", () => {
	for (const command of [
		"printf ready && kubectl delete pod api",
		"printf ready || terraform apply",
		"printf pod | xargs kubectl delete",
		"kubectl get pods & kubectl delete pod api",
		"$(kubectl delete pod api)",
		"`terraform apply`",
		"K=kubectl $K delete pod api",
		"K=kubectl; $K delete pod api",
		"kube\\ctl delete pod api",
		'ter"ra"form apply',
		"find . -exec /bin/rm -rf {} +",
		"printf target | xargs -n1 /bin/rm",
		'bash -lc "helm uninstall api"',
		'python -c "import os; os.system(\'argocd app sync api\')"',
		"kubectl port-forward service/api 8080:80 & helm uninstall api",
		"$TOOL delete pod api",
		'sudo "$TOOL" apply plan.out',
		'"${KUBECTL}" delete pod api',
		"$'r''m' -rf target",
	]) {
		assert.equal(evaluateCommand(command).allow, false, command);
	}

	for (const command of [
		'printf "%s\\n" "kubectl delete pod api"',
		'printf "%s\\n" "terraform apply"',
		'printf "%s\\n" "rm -rf target"',
		'printf "%s\\n" "$TOOL"',
		'echo "${HOME}"',
		'printf "%s\\n" "helm uninstall api"',
		'printf "%s\\n" "argocd app sync api"',
	]) {
		assert.equal(evaluateCommand(command).allow, true, command);
	}
});

test("wrapper matrix cannot hide guarded executables", () => {
	const riskyCommands = [
		"kubectl delete pod api",
		"terraform apply plan.out",
		"helm upgrade api ./chart",
		"argocd app sync api",
		"rm -rf target",
	];
	const wrappers = [
		(command: string) => command,
		(command: string) => `sudo -n ${command}`,
		(command: string) => `env TEST_GUARD=1 ${command}`,
		(command: string) => `command ${command}`,
		(command: string) => `nice -n 5 ${command}`,
		(command: string) => `nohup ${command}`,
		(command: string) => `time -p ${command}`,
		(command: string) => `/usr/bin/env TEST_GUARD=1 ${command}`,
	];
	for (const risky of riskyCommands) {
		for (const wrap of wrappers) {
			const command = wrap(risky);
			assert.equal(evaluateCommand(command).allow, false, command);
		}
	}

	for (const command of [
		"sudo -n kubectl get pods",
		"env KUBECONFIG=test kubectl logs deployment/api",
		"command kubectl describe pod/api",
		"nice -n 5 terraform plan",
		"time -p terraform validate",
		"/usr/bin/env TF_IN_AUTOMATION=1 terraform state list",
	]) {
		assert.equal(evaluateCommand(command).allow, true, command);
	}
});

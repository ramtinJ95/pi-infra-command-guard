import assert from "node:assert/strict";
import { DEFAULT_GUARD_SETTINGS, type GuardedExecutable } from "./guarded-executables.ts";
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

test("aws allows explicit reads and guards mutations or sensitive reads", () => {
	for (const command of [
		"aws --profile production ec2 describe-instances",
		"aws ec2 describe-instances --region us-east-1",
		"aws ec2 --debug describe-instances",
		"sudo /usr/local/bin/aws s3 ls s3://releases",
		"aws sts get-caller-identity",
		"aws dynamodb scan --table-name jobs",
		"aws cloudformation validate-template --template-body file://template.yaml",
		"aws configure list-profiles",
		"aws --version",
	]) {
		assert.equal(evaluateCommand(command).allow, true, command);
	}

	for (const command of [
		"aws ec2 terminate-instances --instance-ids i-123",
		"aws ec2 terminate-instances --instance-ids i-123 --dry-run",
		"aws s3 cp artifact.zip s3://releases/artifact.zip",
		"aws cloudformation deploy --stack-name production",
		"aws secretsmanager list-secrets",
		"aws secretsmanager get-secret-value --secret-id database",
		"aws ssm get-parameter --name /production/password --with-decryption",
		"aws ssm get-parameter-history --name /production/password --with-decryption",
		"aws ecr get-login-password",
		"aws eks get-token --cluster-name production",
		"aws apigateway get-api-key --api-key abc --include-value",
		"aws lambda get-function-configuration --function-name api",
		"aws lambda list-functions",
		"aws ecs describe-task-definition --task-definition api",
		"aws sts get-session-token",
		"aws configure export-credentials",
		"aws madeup inspect-resource",
	]) {
		assert.equal(evaluateCommand(command).allow, false, command);
	}
});

test("az allows explicit reads and guards mutations or sensitive reads", () => {
	for (const command of [
		"az --subscription production vm list --resource-group api",
		"az vm --subscription production list",
		"az vm show --ids /subscriptions/example/resourceGroups/api/providers/Microsoft.Compute/virtualMachines/web",
		"az group exists --name production",
		"az deployment group what-if --resource-group api --template-file main.bicep",
		"az monitor metrics list --resource vm-id",
		"az keyvault key list --vault-name production",
		"az lock list --resource-group production",
		"az restore-point collection list --resource-group production --vm-name web",
		"az search service list --resource-group production",
		"az account show",
		"az version",
	]) {
		assert.equal(evaluateCommand(command).allow, true, command);
	}

	for (const command of [
		"az vm delete --resource-group api --name web --yes",
		"az group create --name production --location westus",
		"az search service delete --name index --resource-group production",
		"az account set --subscription production",
		"az login",
		"az account get-access-token",
		"az aks get-credentials --resource-group api --name production",
		"az keyvault secret list --vault-name production",
		"az keyvault secret show --vault-name production --name database",
		"az storage account keys list --resource-group api --account-name data",
		"az storage blob lease acquire list",
		"az webapp config appsettings list --resource-group api --name web",
		"az rest --method get --url https://management.azure.com/subscriptions",
	]) {
		assert.equal(evaluateCommand(command).allow, false, command);
	}
});

test("gcloud allows explicit reads and guards mutations or sensitive reads", () => {
	for (const command of [
		"gcloud --project production compute instances list",
		"gcloud compute --project production instances list",
		"gcloud compute instances describe web --zone us-central1-a",
		"gcloud projects get-iam-policy production",
		"gcloud logging read 'severity>=ERROR' --limit 10",
		"gcloud asset search-all-resources --scope organizations/123",
		"gcloud components list",
		"gcloud config get-value project",
		"gcloud auth list",
		"gcloud run services list",
		"gcloud deploy releases list --delivery-pipeline api --region us-central1",
		"gcloud info",
	]) {
		assert.equal(evaluateCommand(command).allow, true, command);
	}

	for (const command of [
		"gcloud compute instances delete web --zone us-central1-a --quiet",
		"gcloud run deploy api --image us-docker.pkg.dev/project/api",
		"gcloud storage cp list gs://production-bucket/list",
		"gcloud config set project production",
		"gcloud auth print-access-token",
		"gcloud container clusters get-credentials production --region us-central1",
		"gcloud secrets versions list database",
		"gcloud secrets versions access latest --secret database",
		"gcloud alpha compute instances list",
		"gcloud --flags-file flags.yaml compute instances list",
		"gcloud compute instances inspect web",
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
		"kubectl port-forward service/api 8080:80 & aws ec2 terminate-instances --instance-ids i-123",
		"aws ec2 terminate-instances --instance-ids i-123",
		"az vm delete --resource-group api --name web",
		"gcloud compute instances delete web --zone us-central1-a",
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
		'printf "%s\\n" "aws ec2 terminate-instances"',
		'printf "%s\\n" "az vm delete"',
		'printf "%s\\n" "gcloud compute instances delete"',
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
		"aws ec2 terminate-instances --instance-ids i-123",
		"az vm delete --resource-group api --name web",
		"gcloud compute instances delete web --zone us-central1-a",
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
		"sudo -n aws ec2 describe-instances",
		"env AZURE_CORE_ONLY_SHOW_ERRORS=1 az vm list",
		"command gcloud projects list",
	]) {
		assert.equal(evaluateCommand(command).allow, true, command);
	}
});

test("individual guard toggles bypass only their configured CLI", () => {
	const riskyCommands: Record<GuardedExecutable, string> = {
		argocd: "argocd app sync api",
		aws: "aws ec2 terminate-instances --instance-ids i-123",
		az: "az vm delete --resource-group api --name web",
		gcloud: "gcloud compute instances delete web --zone us-central1-a",
		helm: "helm uninstall api",
		kubectl: "kubectl delete pod api",
		rm: "rm -rf target",
		terraform: "terraform apply",
	};

	for (const [executable, command] of Object.entries(riskyCommands) as Array<[GuardedExecutable, string]>) {
		const settings = { ...DEFAULT_GUARD_SETTINGS, [executable]: false };
		assert.equal(evaluateCommand(command, settings).allow, true, executable);
		assert.equal(evaluateCommand(`sudo ${command}`, settings).allow, true, `wrapped ${executable}`);
		assert.equal(evaluateCommand(`${command} terraform`, settings).allow, true, `enabled guard name as argument to ${executable}`);
		assert.equal(
			evaluateCommand(`${command} && kubectl delete pod still-guarded`, settings).allow,
			executable === "kubectl",
			`mixed ${executable}`,
		);
	}
});

test("disabling every guard bypasses ambiguity and interactive-session restrictions", () => {
	const disabled = Object.fromEntries(
		Object.keys(DEFAULT_GUARD_SETTINGS).map((executable) => [executable, false]),
	) as Record<GuardedExecutable, boolean>;
	for (const command of ["$TOOL delete target", 'bash -lc "rm -rf target"', "kubectl delete pod api && terraform apply"]) {
		assert.equal(evaluateCommand(command, disabled).allow, true, command);
	}
});

test("disabled guards compose with enabled guards without hiding them", () => {
	const settings = { ...DEFAULT_GUARD_SETTINGS, rm: false };
	assert.equal(evaluateCommand('bash -lc "rm -rf target"', settings).allow, true);
	assert.equal(evaluateCommand("rm terraform && terraform plan", settings).allow, true);
	assert.equal(evaluateCommand("rm terraform && terraform apply", settings).allow, false);
	assert.equal(evaluateCommand("$TOOL delete target", settings).allow, false);
});

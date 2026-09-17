import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./test-harness.ts";
import {
	LOW_CONFIDENCE_THRESHOLD,
	REVIEW_VERDICTS,
	TYPESAFE_ENDPOINT_PATH,
	TYPESAFE_MODEL,
	TypeSafeReviewStore,
	buildReviewRequest,
	parseTypeSafeSettings,
	persistTypeSafeEnabled,
	redactCredentials,
	redactReason,
	reviewAdvisory,
	sanitizeExternalText,
	skippedReviewAdvisory,
	type ReviewOutcome,
	type ReviewTransport,
	type ReviewVerdict,
} from "./typesafe.ts";

const SETTINGS = { enabled: true, timeoutMs: 1000 } as const;

type RecordedCall = { url: string; init: RequestInit; body: any };

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function judgedBody(verdict: ReviewVerdict, confidence = 0.9, model = TYPESAFE_MODEL): unknown {
	const rest = (1 - confidence) / (REVIEW_VERDICTS.length - 1);
	const probabilities = Object.fromEntries(REVIEW_VERDICTS.map((candidate) => [candidate, candidate === verdict ? confidence : rest]));
	return {
		model,
		answers: { reason_match: { type: "choice", choice: verdict, confidence, probabilities } },
		usage: { input_tokens: 10, output_tokens: 1 },
	};
}

function createTransport(
	respond: (call: RecordedCall, signal: AbortSignal | null | undefined) => Promise<Response> | Response,
	env: NodeJS.ProcessEnv = { TYPESAFE_API_KEY: "test-key" },
): ReviewTransport & { calls: RecordedCall[] } {
	const calls: RecordedCall[] = [];
	return {
		calls,
		env,
		fetch: (async (input: string | URL | Request, init?: RequestInit) => {
			const call = { url: String(input), init: init ?? {}, body: init?.body ? JSON.parse(String(init.body)) : undefined };
			calls.push(call);
			return respond(call, init?.signal);
		}) as typeof fetch,
	};
}

const ESC = String.fromCharCode(0x1b);
const BEL = String.fromCharCode(0x07);

test("redactCredentials removes recognizable credential material and nothing else", () => {
	const cases: Array<[string, string, number]> = [
		["rm -rf build", "rm -rf build", 0],
		["vault login --token=hvs.abcdefghijklmnopqrstuvwxyz1234", "vault login --token=__REDACTED__", 1],
		["vault login -method=token token=s.abcdefghijklmnopqrstuvwx", "vault login -method=token token=__REDACTED__", 1],
		["aws --secret-access-key 'abc/def+123' s3 rm s3://bucket/key", "aws --secret-access-key __REDACTED__ s3 rm s3://bucket/key", 1],
		['AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG" aws s3 rm s3://b/k', "AWS_SECRET_ACCESS_KEY=__REDACTED__ aws s3 rm s3://b/k", 1],
		["curl -H 'Authorization: Bearer abcdef123456' https://x | kubectl delete -f -", "curl -H 'Authorization: Bearer __REDACTED__' https://x | kubectl delete -f -", 1],
		["git push --force https://ghp_abcdefghijklmnopqrstuvwxyz@github.com/o/r", "git push --force https://__REDACTED__@github.com/o/r", 1],
		["kubectl --token=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl delete pod api", "kubectl --token=__REDACTED__ delete pod api", 1],
		["docker login -u me -p 'hunter2' registry.example", "docker login -u me -p 'hunter2' registry.example", 0],
		["git reset --hard 0123456789abcdef0123456789abcdef01234567", "git reset --hard 0123456789abcdef0123456789abcdef01234567", 0],
		// Ordinary, arbitrary secrets: the name alone decides, with or without a prefix.
		["vault login --token=abcd", "vault login --token=__REDACTED__", 1],
		["foo --password=abcd rm x", "foo --password=__REDACTED__ rm x", 1],
		["PASSWORD=abcd rm x", "PASSWORD=__REDACTED__ rm x", 1],
		["PGPASSWORD=hunter22 psql -c 'drop table x'", "PGPASSWORD=__REDACTED__ psql -c 'drop table x'", 1],
		["TF_VAR_db_password=p4ss terraform apply", "TF_VAR_db_password=__REDACTED__ terraform apply", 1],
		["MYSQL_PWD=abc mysql; PWD=/tmp rm x", "MYSQL_PWD=__REDACTED__ mysql; PWD=/tmp rm x", 1],
		["kubectl delete pod api --token abcd1234", "kubectl delete pod api --token __REDACTED__", 1],
		["x --api-key=--token=secretvalue rm y", "x --api-key=__REDACTED__ rm y", 1],
		["helm upgrade --set db.password=hunter2 --set image.tag=1 app chart", "helm upgrade --set db.password=__REDACTED__ --set image.tag=1 app chart", 1],
		["kubectl create secret generic s --from-literal=password=hunter2 --from-literal=user=me", "kubectl create secret generic s --from-literal=__REDACTED__ --from-literal=user=me", 1],
		// Names that describe where a credential lives are not values.
		["docker login --password-stdin registry.example < pw.txt", "docker login --password-stdin registry.example < pw.txt", 0],
		["vault login --token-file /tmp/t && rm x", "vault login --token-file /tmp/t && rm x", 0],
		["--no-token rm x", "--no-token rm x", 0],
		["TOKEN= rm x", "TOKEN= rm x", 0],
		// Separated values never cross an operator or swallow another option.
		["--token | rm y", "--token | rm y", 0],
		["cmd --token\n rm y", "cmd --token\n rm y", 0],
		["--token -x rm y", "--token -x rm y", 0],
		// Whole shell words: escaped quotes and concatenated segments leave no suffix.
		['AWS_SECRET="first\\"second" rm target', "AWS_SECRET=__REDACTED__ rm target", 1],
		['FOO_TOKEN="a"b rm y', "FOO_TOKEN=__REDACTED__ rm y", 1],
		["FOO_TOKEN=a'b c' rm y", "FOO_TOKEN=__REDACTED__ rm y", 1],
		['env "TOKEN=abc" rm x', "env TOKEN=__REDACTED__ rm x", 1],
		// Words inside substitutions are seen; substitutions themselves are not secrets.
		['echo "$(vault read --token=abcd secret/x)" | rm -rf -', 'echo "$(vault read --token=__REDACTED__ secret/x)" | rm -rf -', 1],
		["TOKEN=$(cat secret.txt) rm x", "TOKEN=$(cat secret.txt) rm x", 0],
		["rm -rf build # it's fine", "rm -rf build # it's fine", 0],
		// A redacted value is hidden wherever else it appears.
		["TOKEN=supersecret rm supersecret-file && echo supersecret", "TOKEN=__REDACTED__ rm __REDACTED__-file && echo __REDACTED__", 3],
	];
	for (const [input, expected, redactions] of cases) {
		const result = redactCredentials(input);
		assert.equal(result.error, undefined, input);
		assert.deepEqual({ text: result.text, redactions: result.redactions }, { text: expected, redactions }, input);
	}
});

test("redaction keeps shell structure intact and refuses to guess at unresolved quoting", () => {
	// The placeholder is a plain word, so the redacted command still parses as
	// an assignment followed by the same operation, never as a redirection.
	const shellSafe = redactCredentials("AWS_SECRET_ACCESS_KEY=example rm target");
	assert.equal(shellSafe.text, "AWS_SECRET_ACCESS_KEY=__REDACTED__ rm target");
	assert.doesNotMatch(shellSafe.text, /[<>]/);
	assert.deepEqual(shellSafe.values, ["example"]);

	for (const [input, error] of [
		["rm 'unterminated", "unterminated quote"],
		['rm "unterminated', "unterminated quote"],
		["rm x \\", "trailing backslash"],
		["rm $(cat list", "unclosed command substitution or subshell"],
	]) {
		assert.deepEqual(redactCredentials(input!), { text: "", redactions: 0, values: [], error }, input);
	}
});

test("redactReason hides credential material echoed from the command", () => {
	assert.deepEqual(
		redactReason("vault login hvs.abcdefghijklmnopqrstuvwxyz1234 accesses or changes security-critical Vault state", []),
		{ text: "vault login __REDACTED__ accesses or changes security-critical Vault state", redactions: 1 },
	);
	assert.deepEqual(
		redactReason("vault login token=s.abcdefghijklmnopqrstuvwx accesses or changes security-critical Vault state", []),
		{ text: "vault login token=__REDACTED__ accesses or changes security-critical Vault state", redactions: 1 },
	);
	// Values redacted from the command are hidden even when the reason quotes
	// them bare, and prose quoting is never an error.
	assert.deepEqual(
		redactReason("vault write secret/x with value 'abc/def+123' isn't allowed", ["abc/def+123"]),
		{ text: "vault write secret/x with value '__REDACTED__' isn't allowed", redactions: 1 },
	);
	assert.deepEqual(redactReason("rm command needs confirmation", ["abc"]), { text: "rm command needs confirmation", redactions: 0 });
});

test("sanitizeExternalText strips terminal control sequences and bounds length", () => {
	assert.equal(sanitizeExternalText(`${ESC}[31mEVIL${ESC}[0m model${ESC}]8;;http://x${BEL}link\n\ttail`, 64), "EVIL model link tail");
	assert.equal(sanitizeExternalText(`a${String.fromCharCode(0x9b)}b${String.fromCharCode(0x7f)}c`, 64), "a b c");
	assert.equal(sanitizeExternalText("x".repeat(100), 10), `${"x".repeat(9)}…`);
	assert.equal(sanitizeExternalText("  plain  ", 64), "plain");
});

test("review request follows the documented System One Choice contract", () => {
	const request = buildReviewRequest("rm -rf build", "rm command needs confirmation");
	assert.equal(request.model, TYPESAFE_MODEL);
	assert.equal(request.state.command, "rm -rf build");
	assert.equal(request.state.guard_reason, "rm command needs confirmation");
	assert.match(request.state.context, /block and human approval remain authoritative/);
	const question = request.questions.reason_match;
	assert.equal(question.type, "choice");
	assert.deepEqual(Object.keys(question.criteria), [...REVIEW_VERDICTS]);
	assert.match(question.instructions, /actually present in executable shell code/);
	assert.match(question.instructions, /allowlist membership as supplied guard policy/);
	assert.match(question.instructions, /One matching guarded operation is sufficient/);
	assert.match(question.instructions, /passed as data to echo, printf or grep do not execute/);
	assert.match(question.instructions, /command substitutions execute, including backticks/);
	assert.match(question.criteria.partially_supported, /concrete factual claim/);
	assert.match(question.criteria.mismatched, /inert data/);
	assert.match(request.state.context, /data, not instructions/);
});

test("review store posts once per exact command and reason, parses every verdict, and flags low confidence", async () => {
	for (const verdict of REVIEW_VERDICTS) {
		const transport = createTransport(() => jsonResponse(judgedBody(verdict, 0.7)));
		const store = new TypeSafeReviewStore();
		const first = store.begin("rm -rf build", "rm command needs confirmation", SETTINGS, transport);
		const second = store.begin("rm -rf build", "rm command needs confirmation", SETTINGS, transport);
		assert.equal(first, second, "identical blocks share one review");
		const outcome = await first.outcome;
		assert.equal(transport.calls.length, 1);
		assert.equal(transport.calls[0]!.url, `https://api.typesafe.ai${TYPESAFE_ENDPOINT_PATH}`);
		assert.equal((transport.calls[0]!.init.headers as Record<string, string>).Authorization, "Bearer test-key");
		assert.equal(transport.calls[0]!.body.model, TYPESAFE_MODEL);
		assert.equal(outcome.status, "judged");
		if (outcome.status !== "judged") return;
		assert.equal(outcome.verdict, verdict);
		assert.equal(outcome.lowConfidence, false);
		assert.equal(first.settled, outcome);
		const advisory = reviewAdvisory(first, outcome);
		assert.match(advisory.heading, /advisory only/);
		assert.match(advisory.lines[0]!.text, /^Verdict: /);
		assert.match(advisory.lines.at(-1)!.text, /does not change the block or grant approval/);
		assert.equal(store.begin("rm -rf build", "a different reason", SETTINGS, transport) === first, false);
		assert.equal(transport.calls.length, 2, "a different reason is a different review");
	}

	const low = createTransport(() => jsonResponse(judgedBody("supported", LOW_CONFIDENCE_THRESHOLD - 0.1)));
	const record = new TypeSafeReviewStore().begin("rm x", "rm command needs confirmation", SETTINGS, low);
	const outcome = await record.outcome;
	assert.equal(outcome.status, "judged");
	if (outcome.status !== "judged") return;
	assert.equal(outcome.lowConfidence, true);
	const advisory = reviewAdvisory(record, outcome);
	assert.match(advisory.lines[0]!.text, /unclear — options are close/);
	assert.equal(advisory.lines[0]!.style, "warning");
	assert.match(advisory.lines[2]!.text, /not whether the verdict is correct/);
});

test("review store honours TYPESAFE_BASE_URL and reports redactions in the advisory", async () => {
	const transport = createTransport(() => jsonResponse(judgedBody("supported")), {
		TYPESAFE_API_KEY: "k",
		TYPESAFE_BASE_URL: "https://proxy.example/typesafe/",
	});
	const record = new TypeSafeReviewStore().begin(
		"vault login --token=hvs.abcdefghijklmnopqrstuvwxyz1234",
		"vault login can change authentication state",
		SETTINGS,
		transport,
	);
	const outcome = await record.outcome;
	assert.equal(transport.calls[0]!.url, `https://proxy.example/typesafe${TYPESAFE_ENDPOINT_PATH}`);
	assert.equal(transport.calls[0]!.body.state.command, "vault login --token=__REDACTED__");
	assert.equal(record.redactions, 1);
	assert.match(reviewAdvisory(record, outcome).lines.at(-2)!.text, /1 credential-like value redacted\) and the guard reason\./);
});

test("review store redacts both outbound fields and keeps the exact originals for identity", async () => {
	const token = "hvs.abcdefghijklmnopqrstuvwxyz1234";
	const command = `vault login ${token} policy`;
	const reason = `vault login ${token} accesses or changes security-critical Vault state`;
	const transport = createTransport(() => jsonResponse(judgedBody("supported")));
	const store = new TypeSafeReviewStore();
	const record = store.begin(command, reason, SETTINGS, transport);
	await record.outcome;
	assert.equal(transport.calls.length, 1);
	const request = transport.calls[0]!.init;
	assert.doesNotMatch(String(request.body), new RegExp(token.replace(/\./g, "\\.")), "no request field carries the token");
	assert.doesNotMatch(JSON.stringify({ url: transport.calls[0]!.url, headers: request.headers, body: request.body }), /hvs\./);
	assert.equal(transport.calls[0]!.body.state.command, "vault login __REDACTED__ policy");
	assert.equal(transport.calls[0]!.body.state.guard_reason, "vault login __REDACTED__ accesses or changes security-critical Vault state");
	assert.equal(record.command, command, "the original command is kept for the approval binding");
	assert.equal(record.reason, reason, "the original reason is kept for the approval binding");
	assert.equal(record.sentCommand, "vault login __REDACTED__ policy");
	assert.equal(record.sentReason, "vault login __REDACTED__ accesses or changes security-critical Vault state");
	assert.equal(record.reasonRedactions, 1);
	assert.equal(store.lookup(command, reason), record, "cache identity uses the originals");
	assert.equal(store.lookup(record.sentCommand, record.sentReason), undefined);
	assert.match(reviewAdvisory(record, record.settled!).lines.at(-2)!.text, /1 credential-like value redacted\) and the guard reason \(1 redacted\)/);
});

test("review store never sends a command whose quoting it cannot resolve", async () => {
	const transport = createTransport(() => jsonResponse(judgedBody("supported")));
	const store = new TypeSafeReviewStore();
	const record = store.begin("rm 'oops", "rm command needs confirmation", SETTINGS, transport);
	const outcome = await record.outcome;
	assert.deepEqual(outcome, {
		status: "not-sent",
		detail: "credential redaction could not resolve the command's quoting (unterminated quote)",
	});
	assert.equal(transport.calls.length, 0, "nothing is sent");
	assert.equal(record.sentCommand, "");
	assert.equal(record.sentReason, "");
	const advisory = reviewAdvisory(record, outcome);
	assert.match(advisory.lines[0]!.text, /^Not sent: credential redaction could not resolve the command's quoting \(unterminated quote\)\. Nothing about this command was sent to TypeSafe\./);
	assert.equal(advisory.lines[0]!.style, "warning");
	assert.equal(store.lookup("rm 'oops", "rm command needs confirmation"), record, "the visible failure is cached like any outcome");
});

test("review store makes failures explicit: credentials, HTTP errors, malformed answers, network, timeout, abort", async () => {
	const missing = new TypeSafeReviewStore().begin("rm x", "rm command needs confirmation", SETTINGS, createTransport(() => jsonResponse({}), {}));
	assert.deepEqual(await missing.outcome, { status: "missing-credentials", detail: "TYPESAFE_API_KEY is not set in Pi's environment" });
	assert.match(reviewAdvisory(missing, missing.settled!).lines[0]!.text, /TYPESAFE_API_KEY is not set/);

	const unauthorized = await new TypeSafeReviewStore()
		.begin("rm x", "r", SETTINGS, createTransport(() => jsonResponse({ detail: "Invalid API key" }, 401))).outcome;
	assert.deepEqual(unauthorized, { status: "failed", detail: "HTTP 401 (check TYPESAFE_API_KEY): Invalid API key" });
	const overloaded = await new TypeSafeReviewStore()
		.begin("rm x", "r", SETTINGS, createTransport(() => new Response("busy", { status: 529 }))).outcome;
	assert.deepEqual(overloaded, { status: "failed", detail: "HTTP 529 (service overloaded)" });

	const malformed: Array<[unknown, RegExp]> = [
		[{ model: TYPESAFE_MODEL }, /no answers/],
		[{ answers: { reason_match: { type: "noul", noul: 0.4 } } }, /no choice answer/],
		[{ answers: { reason_match: { type: "choice", choice: "safe", confidence: 0.9, probabilities: {} } } }, /not a known verdict: safe/],
		[{ answers: { reason_match: { type: "choice", choice: "supported", confidence: 1.5, probabilities: {} } } }, /confidence is not a number/],
		[{ answers: { reason_match: { type: "choice", choice: "supported", confidence: 0.9, probabilities: { supported: 0.9 } } } }, /missing a probability for partially_supported/],
	];
	for (const [body, expected] of malformed) {
		const outcome = await new TypeSafeReviewStore().begin("rm x", "r", SETTINGS, createTransport(() => jsonResponse(body))).outcome;
		assert.equal(outcome.status, "failed");
		assert.match((outcome as { detail: string }).detail, expected);
	}
	const notJson = await new TypeSafeReviewStore()
		.begin("rm x", "r", SETTINGS, createTransport(() => new Response("<html>", { status: 200 }))).outcome;
	assert.deepEqual(notJson, { status: "failed", detail: "response body is not JSON" });

	const network = await new TypeSafeReviewStore()
		.begin("rm x", "r", SETTINGS, createTransport(() => Promise.reject(new Error("ECONNREFUSED")))).outcome;
	assert.deepEqual(network, { status: "failed", detail: "ECONNREFUSED" });

	const waitForAbort = (signal: AbortSignal | null | undefined) =>
		new Promise<Response>((_, reject) => signal?.addEventListener("abort", () => reject(new Error("aborted"))));
	const slow = new TypeSafeReviewStore().begin("rm x", "r", { enabled: true, timeoutMs: 20 }, createTransport((_call, signal) => waitForAbort(signal)));
	assert.deepEqual(await slow.outcome, { status: "timed-out", timeoutMs: 20 });
	assert.match(reviewAdvisory(slow, slow.settled!).lines[0]!.text, /did not answer within 20 ms/);

	const store = new TypeSafeReviewStore();
	const inFlight = store.begin("rm x", "r", SETTINGS, createTransport((_call, signal) => waitForAbort(signal)));
	assert.equal(store.size(), 1);
	store.clear();
	assert.deepEqual(await inFlight.outcome, { status: "aborted" });
	assert.equal(store.size(), 0);
	assert.equal(store.lookup("rm x", "r"), undefined);
});

test("review store expires cached reviews with the approval TTL and describes its pause", async () => {
	let now = 1_000;
	const transport = createTransport(() => jsonResponse(judgedBody("supported")));
	const store = new TypeSafeReviewStore(() => now);
	const first = store.begin("rm x", "r", SETTINGS, transport);
	await first.outcome;
	now += 10 * 60 * 1000;
	assert.equal(store.lookup("rm x", "r"), undefined);
	const second = store.begin("rm x", "r", SETTINGS, transport);
	assert.notEqual(second, first);
	assert.equal(transport.calls.length, 2);
	assert.deepEqual(store.describe(), []);
	store.pause.pause(30 * 60 * 1000);
	assert.deepEqual(store.describe(), ["TypeSafe review paused for 30 minutes"]);
});

test("skipped advisories explain why no review exists", () => {
	assert.match(skippedReviewAdvisory("not-known-risk").lines[0]!.text, /positively recognized risk/);
	assert.match(skippedReviewAdvisory("not-requested").lines[0]!.text, /disabled, paused, or unavailable/);
	const outcome: ReviewOutcome = { status: "aborted" };
	assert.match(
		reviewAdvisory(
			{ command: "", reason: "", sentCommand: "", sentReason: "", redactions: 0, reasonRedactions: 0, startedAt: 0, abort: new AbortController(), outcome: Promise.resolve(outcome) },
			outcome,
		)
			.lines[0]!.text,
		/cancelled before it completed/,
	);
});

test("TypeSafe settings default off and validate their bounds", () => {
	assert.deepEqual(parseTypeSafeSettings(undefined), { enabled: false, timeoutMs: 8000 });
	assert.deepEqual(parseTypeSafeSettings({}), { enabled: false, timeoutMs: 8000 });
	assert.deepEqual(parseTypeSafeSettings({ enabled: true, timeoutMs: 30000 }), { enabled: true, timeoutMs: 30000 });
	assert.throws(() => parseTypeSafeSettings([]), /must be a JSON object/);
	assert.throws(() => parseTypeSafeSettings({ enabled: 1 }), /enabled must be true or false/);
	assert.throws(() => parseTypeSafeSettings({ timeoutMs: 30001 }), /between 1000 and 30000/);
	assert.throws(() => parseTypeSafeSettings({ timeoutMs: 1500.5 }), /between 1000 and 30000/);
	assert.throws(() => parseTypeSafeSettings({ model: "jev-latest" }), /unknown field: model/);
});

test("persistTypeSafeEnabled preserves other configuration and refuses to rewrite invalid JSON", () => {
	const directory = mkdtempSync(join(tmpdir(), "infra-command-guard-typesafe-config-"));
	try {
		const configPath = join(directory, "nested", "infra-command-guard.json");
		assert.deepEqual(persistTypeSafeEnabled(configPath, true), { ok: true });
		assert.deepEqual(JSON.parse(readFileSync(configPath, "utf8")), { integrations: { typesafe: { enabled: true } } });

		writeFileSync(configPath, JSON.stringify({
			guards: { az: false },
			integrations: { herdr: { enabled: false }, typesafe: { enabled: true, timeoutMs: 2000 } },
		}));
		assert.deepEqual(persistTypeSafeEnabled(configPath, false), { ok: true });
		assert.deepEqual(JSON.parse(readFileSync(configPath, "utf8")), {
			guards: { az: false },
			integrations: { herdr: { enabled: false }, typesafe: { enabled: false, timeoutMs: 2000 } },
		});
		assert.ok(readFileSync(configPath, "utf8").endsWith("}\n"));

		writeFileSync(configPath, "{ not json");
		const refused = persistTypeSafeEnabled(configPath, true);
		assert.equal(refused.ok, false);
		assert.match((refused as { error: string }).error, /refusing to rewrite/);
		assert.equal(readFileSync(configPath, "utf8"), "{ not json");

		writeFileSync(configPath, "[]");
		assert.equal(persistTypeSafeEnabled(configPath, true).ok, false);
		assert.equal(readFileSync(configPath, "utf8"), "[]");
	} finally {
		rmSync(directory, { recursive: true, force: true });
	}
});

test("persistTypeSafeEnabled replaces the file atomically, keeps its permissions, and leaves the original intact on failure", () => {
	const directory = mkdtempSync(join(tmpdir(), "infra-command-guard-typesafe-atomic-"));
	const configDirectory = join(directory, "agent");
	const configPath = join(configDirectory, "infra-command-guard.json");
	try {
		mkdirSync(configDirectory);
		const original = JSON.stringify({ guards: { az: false }, integrations: { typesafe: { enabled: false } } });
		writeFileSync(configPath, original, { mode: 0o600 });
		assert.deepEqual(persistTypeSafeEnabled(configPath, true), { ok: true });
		assert.equal(statSync(configPath).mode & 0o777, 0o600, "the original permissions are preserved");
		assert.equal(JSON.parse(readFileSync(configPath, "utf8")).integrations.typesafe.enabled, true);
		assert.deepEqual(readdirSync(configDirectory), ["infra-command-guard.json"], "no temporary sibling is left behind");

		if (typeof process.getuid === "function" && process.getuid() === 0) return;
		// A read-only directory makes the temporary sibling impossible to create;
		// the original must be untouched and no temporary file may remain.
		const before = readFileSync(configPath, "utf8");
		chmodSync(configDirectory, 0o500);
		try {
			const failed = persistTypeSafeEnabled(configPath, false);
			assert.equal(failed.ok, false);
			assert.match((failed as { error: string }).error, /EACCES|EPERM|permission denied/i);
		} finally {
			chmodSync(configDirectory, 0o700);
		}
		assert.equal(readFileSync(configPath, "utf8"), before, "a failed write leaves the original byte-for-byte");
		assert.equal(statSync(configPath).mode & 0o777, 0o600);
		assert.deepEqual(readdirSync(configDirectory), ["infra-command-guard.json"]);
	} finally {
		try {
			chmodSync(configDirectory, 0o700);
		} catch {}
		rmSync(directory, { recursive: true, force: true });
	}
});

test("hostile TypeSafe responses cannot carry control sequences into outcomes", async () => {
	const hostileModel = `${ESC}[2J${ESC}[31mjev${ESC}]0;owned${BEL}-latest`;
	const judged = await new TypeSafeReviewStore()
		.begin("rm x", "r", SETTINGS, createTransport(() => jsonResponse(judgedBody("supported", 0.9, hostileModel)))).outcome;
	assert.equal(judged.status, "judged");
	if (judged.status !== "judged") return;
	assert.equal(judged.model, "jev -latest");
	assert.doesNotMatch(JSON.stringify(judged), /\\u001b|\\u0007/);

	const hostileDetail = `${ESC}[31mInvalid${ESC}[0m\nkey${"!".repeat(300)}`;
	const failed = await new TypeSafeReviewStore()
		.begin("rm x", "r", SETTINGS, createTransport(() => jsonResponse({ detail: hostileDetail }, 401))).outcome;
	assert.equal(failed.status, "failed");
	if (failed.status !== "failed") return;
	assert.doesNotMatch(failed.detail, new RegExp(`${ESC}|\n`));
	assert.match(failed.detail, /^HTTP 401 \(check TYPESAFE_API_KEY\): Invalid key!+…$/);
	assert.ok(failed.detail.length < 260);

	const hostileChoice = await new TypeSafeReviewStore()
		.begin("rm x", "r", SETTINGS, createTransport(() => jsonResponse({
			answers: { reason_match: { type: "choice", choice: `${ESC}[5msafe${"e".repeat(100)}`, confidence: 0.9, probabilities: {} } },
		}))).outcome;
	assert.equal(hostileChoice.status, "failed");
	if (hostileChoice.status !== "failed") return;
	assert.doesNotMatch(hostileChoice.detail, new RegExp(ESC));
	assert.ok(hostileChoice.detail.length < 100, hostileChoice.detail);

	const hostileNetwork = await new TypeSafeReviewStore()
		.begin("rm x", "r", SETTINGS, createTransport(() => Promise.reject(new Error(`${ESC}[31mECONNRESET${ESC}[0m`)))).outcome;
	assert.deepEqual(hostileNetwork, { status: "failed", detail: "ECONNRESET" });
});

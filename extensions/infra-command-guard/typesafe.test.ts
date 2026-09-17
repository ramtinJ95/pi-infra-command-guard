import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
	reviewAdvisory,
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

test("redactCredentials removes recognizable credential material and nothing else", () => {
	const cases: Array<[string, string, number]> = [
		["rm -rf build", "rm -rf build", 0],
		["vault login --token=hvs.abcdefghijklmnopqrstuvwxyz1234", "vault login --token=<redacted>", 1],
		["vault login -method=token token=s.abcdefghijklmnopqrstuvwx", "vault login -method=token token=<redacted>", 1],
		["aws --secret-access-key 'abc/def+123' s3 rm s3://bucket/key", "aws --secret-access-key <redacted> s3 rm s3://bucket/key", 1],
		['AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG" aws s3 rm s3://b/k', "AWS_SECRET_ACCESS_KEY=<redacted> aws s3 rm s3://b/k", 1],
		["curl -H 'Authorization: Bearer abcdef123456' https://x | kubectl delete -f -", "curl -H 'Authorization: Bearer <redacted>' https://x | kubectl delete -f -", 1],
		["git push --force https://ghp_abcdefghijklmnopqrstuvwxyz@github.com/o/r", "git push --force https://<redacted>@github.com/o/r", 1],
		["kubectl --token=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl delete pod api", "kubectl --token=<redacted> delete pod api", 1],
		["docker login -u me -p 'hunter2' registry.example", "docker login -u me -p 'hunter2' registry.example", 0],
		["git reset --hard 0123456789abcdef0123456789abcdef01234567", "git reset --hard 0123456789abcdef0123456789abcdef01234567", 0],
	];
	for (const [input, expected, redactions] of cases) {
		assert.deepEqual(redactCredentials(input), { text: expected, redactions }, input);
	}
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
	assert.equal(transport.calls[0]!.body.state.command, "vault login --token=<redacted>");
	assert.equal(record.redactions, 1);
	assert.match(reviewAdvisory(record, outcome).lines.at(-2)!.text, /1 credential-like value redacted/);
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
		reviewAdvisory({ command: "", reason: "", sentCommand: "", redactions: 0, startedAt: 0, abort: new AbortController(), outcome: Promise.resolve(outcome) }, outcome)
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

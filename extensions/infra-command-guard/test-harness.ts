type TestCase = { name: string; run: () => void | Promise<void> };

const tests: TestCase[] = [];

function test(name: string, run: TestCase["run"]): void {
	tests.push({ name, run });
}

async function runTests(): Promise<void> {
	let failures = 0;
	for (const testCase of tests) {
		try {
			await testCase.run();
			process.stdout.write(`ok - ${testCase.name}\n`);
		} catch (error) {
			failures += 1;
			process.stderr.write(`not ok - ${testCase.name}\n${error instanceof Error ? error.stack : String(error)}\n`);
		}
	}
	if (failures > 0) process.exitCode = 1;
}

export { runTests, test };

import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { toolContract } from "../../src/contracts/toolContracts.js";
import { pythonPycFixture } from "../../src/python/PythonPyc.fixture.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest } from "../support/cli/cliFixture.js";

cliTest(
  "reports nested CPython code objects through the public CLI",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-python-pyc-cli-");
    const path = join(root, "sample.pyc");
    await writeFile(path, pythonPycFixture("py311", { nested: true }));
    const result = await cli.run({
      arguments: ["inspect-python-pyc", path, "--json"],
    });
    expect(result.exitCode, result.stderr).toBe(0);
    const evidence = toolContract("inspect_python_pyc").outputSchema.parse(
      result.json,
    );
    expect(evidence.normalized_result.header.python_version).toBe("3.12");
    expect(evidence.normalized_result.code.nested_code[0]?.name).toBe("inner");
  },
);

cliTest(
  "resolves a relative pyc path against the working directory",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-python-pyc-cli-rel-");
    await writeFile(join(root, "sample.pyc"), pythonPycFixture("py37"));
    const result = await cli.run({
      arguments: ["inspect-python-pyc", "sample.pyc", "--json"],
      cwd: root,
    });
    expect(result.exitCode, result.stderr).toBe(0);
    const evidence = toolContract("inspect_python_pyc").outputSchema.parse(
      result.json,
    );
    expect(evidence.normalized_result.header.python_version).toBe("3.7");
    expect(evidence.subject?.local_path).toBe(join(root, "sample.pyc"));
  },
);

cliTest("reports a truncated pyc as invalid input", async ({ cli }) => {
  const root = await createTestTempDirectory("rea-python-pyc-cli-bad-");
  const path = join(root, "broken.pyc");
  await writeFile(path, Buffer.from("not a pyc"));
  const result = await cli.run({
    arguments: ["inspect-python-pyc", path, "--json"],
  });
  expect(result.exitCode).toBe(1);
  expect(result.json).toMatchObject({
    code: "invalid_request",
    details: { operation: "inspect_python_pyc" },
  });
});

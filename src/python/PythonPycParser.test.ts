import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { inspectPythonPycInputSchema } from "../domain/python/pythonPyc.js";
import {
  marshalCode,
  pythonPycFixture,
  pythonPycHeader,
} from "./PythonPyc.fixture.js";
import { parsePythonPyc } from "./PythonPycParser.js";
import { PythonPycFormatFailure } from "./PythonPyc.errors.js";

const defaults = inspectPythonPycInputSchema.parse({
  path: "/artifacts/sample.pyc",
});

const parse = (bytes: Buffer) =>
  parsePythonPyc(
    bytes,
    {
      path: defaults.path,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      bytes: bytes.length,
    },
    defaults,
  );

it("reads 3.7, 3.10 and 3.12 layouts including nested code", () => {
  const py37 = parse(pythonPycFixture("py37"));
  expect(py37.header).toMatchObject({
    magic: 3394,
    python_version: "3.7",
    code_layout: "py37",
    hash_based: false,
  });
  expect(py37.code.posonlyargcount).toBeNull();
  expect(py37.code.nlocals).toBe(0);
  expect(py37.code.qualname).toBeNull();

  const py38 = parse(pythonPycFixture("py38", { nested: true }));
  expect(py38.header.python_version).toBe("3.10");
  expect(py38.code.posonlyargcount).toBe(0);
  expect(py38.code.nested_code[0]?.name).toBe("inner");
  expect(py38.coverage.code_objects).toBe(2);

  const py311 = parse(pythonPycFixture("py311", { nested: true }));
  expect(py311.header).toMatchObject({
    magic: 3531,
    python_version: "3.12",
    code_layout: "py311",
  });
  expect(py311.code.nlocals).toBeNull();
  expect(py311.code.qualname).toBe("<module>");
  expect(py311.code.nested_code[0]?.name).toBe("inner");
  expect(py311.code.consts).toEqual(
    expect.arrayContaining([
      { kind: "code", name: "inner", firstlineno: 2 },
      { kind: "none" },
    ]),
  );
});

it("decodes a hash-based header and a FLAG_REF top-level code object", () => {
  const bytes = pythonPycFixture("py311", {
    flaggedCode: true,
    header: {
      flags: 0x1,
      sourceHash: Buffer.from("0102030405060708", "hex"),
    },
  });
  const report = parse(bytes);
  expect(report.header).toMatchObject({
    hash_based: true,
    check_source: false,
    source_hash_hex: "0102030405060708",
    source_mtime: null,
    source_size: null,
  });
  expect(report.code.name).toBe("<module>");
});

it("fails unknown magics and truncated marshal without partial success", () => {
  const unknown = Buffer.concat([pythonPycHeader(1), marshalCode("py311")]);
  expect(() => parse(unknown)).toThrow(PythonPycFormatFailure);
  expect(() => parse(pythonPycFixture("py311").subarray(0, 20))).toThrow(
    PythonPycFormatFailure,
  );
});

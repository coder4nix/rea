import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { inspectPeCertificatesInputSchema } from "../../domain/native/peCertificates.js";
import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import {
  peCertificateFixture,
  peWithoutCertificateTableFixture,
  pkcs7SignedDataFixture,
} from "./PeCertificates.fixture.js";
import { parsePeCertificates } from "./PeCertificateParser.js";

const defaults = inspectPeCertificatesInputSchema.parse({
  path: "/artifacts/app.exe",
});

const parse = (bytes: Buffer) =>
  parsePeCertificates(
    bytes,
    {
      path: defaults.path,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      bytes: bytes.length,
    },
    defaults,
  );

it("reads PE32 and PE32+ PKCS#7 certificate tables", () => {
  for (const plus of [false, true]) {
    const bytes = peCertificateFixture(plus);
    const report = parse(bytes);
    expect(report.format).toBe(plus ? "pe32-plus" : "pe32");
    expect(report.table).not.toBeNull();
    expect(report.entries).toHaveLength(1);
    expect(report.entries[0]).toMatchObject({
      revision: 0x0200,
      certificate_type: 2,
      certificate_type_name: "pkcs7",
    });
    expect(report.entries[0]?.pkcs7).toMatchObject({
      content_type_oid: "1.2.840.113549.1.7.2",
      content_type_name: "signedData",
      digest_algorithm_oids: ["2.16.840.1.101.3.4.2.1"],
    });
    const certificate = report.entries[0]?.pkcs7?.certificates[0];
    expect(certificate?.serial_hex).toBe("11223344");
    expect(certificate?.subject.text).toContain("commonName=REA Fixture");
    expect(certificate?.not_before).toBe("250101000000Z");
    expect(report.coverage).toEqual({
      status: "complete",
      examined_entries: 1,
      certificates: 1,
    });
  }
});

it("reports an absent security directory without claiming the image is unsigned", () => {
  const report = parse(peWithoutCertificateTableFixture());
  expect(report.table).toBeNull();
  expect(report.entries).toEqual([]);
  expect(report.limitations[0]).toMatch(
    /IMAGE_DIRECTORY_ENTRY_SECURITY is absent/u,
  );
});

it("fails truncated WIN_CERTIFICATE payloads without partial success", () => {
  const bytes = peCertificateFixture();
  const tableOffset = bytes.readUInt32LE(0x80 + 24 + 96 + 32);
  bytes.writeUInt32LE(4, tableOffset);
  expect(() => parse(bytes)).toThrow(ArtifactReaderFailure);
});

it("fails PKCS#7 payloads that are not signedData", () => {
  const bytes = peCertificateFixture(false, Buffer.from("not-pkcs7"), 0x0002);
  expect(() => parse(bytes)).toThrow(ArtifactReaderFailure);
});

it("keeps unknown certificate types as payload hashes without PKCS#7 projection", () => {
  const payload = pkcs7SignedDataFixture();
  const report = parse(peCertificateFixture(false, payload, 0x0001));
  expect(report.entries[0]).toMatchObject({
    certificate_type_name: "x509",
    pkcs7: null,
  });
  expect(report.entries[0]?.payload.sha256).toBe(
    createHash("sha256").update(payload).digest("hex"),
  );
});

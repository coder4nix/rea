const OID_NAMES: Readonly<Record<string, string>> = {
  "1.2.840.113549.1.7.1": "data",
  "1.2.840.113549.1.7.2": "signedData",
  "1.2.840.113549.1.1.1": "rsaEncryption",
  "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
  "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
  "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
  "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
  "1.2.840.113549.1.9.3": "contentType",
  "1.2.840.113549.1.9.4": "messageDigest",
  "1.2.840.113549.1.9.5": "signingTime",
  "1.3.14.3.2.26": "sha1",
  "2.5.4.3": "commonName",
  "2.5.4.6": "countryName",
  "2.5.4.10": "organizationName",
  "2.5.4.11": "organizationalUnitName",
  "2.16.840.1.101.3.4.2.1": "sha256",
  "2.16.840.1.101.3.4.2.2": "sha384",
  "2.16.840.1.101.3.4.2.3": "sha512",
};

export interface DerNode {
  readonly tag: number;
  readonly constructed: boolean;
  readonly start: number;
  readonly end: number;
  readonly content: Buffer;
  readonly children: readonly DerNode[];
}

export class PeCertificateDerFailure extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PeCertificateDerFailure";
  }
}

const fail = (message: string): never => {
  throw new PeCertificateDerFailure(message);
};

const required = <T>(value: T | undefined, message: string): T =>
  value === undefined ? fail(message) : value;

/** Decode one DER/BER TLV; constructed nodes own their child sequence. */
export const readDer = (
  bytes: Buffer,
  offset = 0,
  end = bytes.length,
  depth = 0,
): DerNode => {
  if (depth > 32) return fail("DER nesting exceeds 32 levels.");
  if (offset >= end || offset + 2 > end)
    return fail("Truncated DER tag or length.");
  const tag = required(bytes[offset], "Truncated DER tag.");
  const constructed = (tag & 0x20) !== 0;
  let cursor = offset + 1;
  const lengthByte = required(bytes[cursor], "Truncated DER length.");
  cursor += 1;
  let length: number;
  if ((lengthByte & 0x80) === 0) length = lengthByte;
  else {
    const width = lengthByte & 0x7f;
    if (width === 0 || width > 4) return fail("Unsupported DER length form.");
    if (cursor + width > end) return fail("Truncated DER long length.");
    length = 0;
    for (let index = 0; index < width; index += 1) {
      length = (length << 8) | required(bytes[cursor], "Truncated DER length.");
      cursor += 1;
    }
  }
  const contentEnd = cursor + length;
  if (length < 0 || contentEnd > end)
    return fail("DER value exceeds its parent.");
  const content = bytes.subarray(cursor, contentEnd);
  const children: DerNode[] = [];
  if (constructed) {
    let at = cursor;
    while (at < contentEnd) {
      const child = readDer(bytes, at, contentEnd, depth + 1);
      children.push(child);
      at = child.end;
    }
  }
  return {
    tag,
    constructed,
    start: offset,
    end: contentEnd,
    content,
    children,
  };
};

export const oidName = (oid: string): string | null => OID_NAMES[oid] ?? null;

/** Decode an OBJECT IDENTIFIER content buffer as dotted decimal. */
export const decodeOid = (content: Buffer): string => {
  if (content.length === 0) return fail("Empty OBJECT IDENTIFIER.");
  const first = required(content[0], "Empty OBJECT IDENTIFIER.");
  const parts = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (let index = 1; index < content.length; index += 1) {
    const byte = required(content[index], "Truncated OBJECT IDENTIFIER.");
    value = (value << 7) | (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      parts.push(value);
      value = 0;
    } else if (index === content.length - 1)
      return fail("Truncated OBJECT IDENTIFIER component.");
  }
  return parts.join(".");
};

const decodeUtf16Be = (bytes: Buffer): string => {
  if (bytes.length % 2 !== 0) return fail("BMPString length is odd.");
  let text = "";
  for (let index = 0; index < bytes.length; index += 2)
    text += String.fromCharCode(bytes.readUInt16BE(index));
  return text;
};

const decodePrintable = (node: DerNode): string => {
  switch (node.tag) {
    case 0x0c:
    case 0x13:
    case 0x16:
    case 0x17:
    case 0x18:
    case 0x1b:
      return node.content.toString("utf8");
    case 0x1e:
      return decodeUtf16Be(node.content);
    default:
      return node.content.toString("latin1");
  }
};

const integerHex = (content: Buffer): string => {
  let start = 0;
  while (start < content.length - 1 && content[start] === 0) start += 1;
  return content.subarray(start).toString("hex");
};

const sequence = (node: DerNode, label: string): readonly DerNode[] => {
  if (node.tag !== 0x30) return fail(`Expected SEQUENCE for ${label}.`);
  return node.children;
};

const algorithmOid = (node: DerNode): string => {
  const children = sequence(node, "AlgorithmIdentifier");
  const oid = children[0];
  if (oid === undefined || oid.tag !== 0x06)
    return fail("AlgorithmIdentifier is missing an OBJECT IDENTIFIER.");
  return decodeOid(oid.content);
};

interface Attribute {
  readonly oid: string;
  readonly oid_name: string | null;
  readonly value: string;
}

const decodeName = (
  node: DerNode,
): {
  readonly text: string;
  readonly attributes: readonly Attribute[];
} => {
  const attributes: Attribute[] = [];
  for (const rdn of sequence(node, "Name")) {
    if (rdn.tag !== 0x31) return fail("Name RDN is not a SET.");
    for (const attribute of rdn.children) {
      const parts = sequence(attribute, "AttributeTypeAndValue");
      const oidNode = parts[0];
      const valueNode = parts[1];
      if (
        oidNode === undefined ||
        oidNode.tag !== 0x06 ||
        valueNode === undefined
      )
        return fail("AttributeTypeAndValue is truncated.");
      const oid = decodeOid(oidNode.content);
      attributes.push({
        oid,
        oid_name: oidName(oid),
        value: decodePrintable(valueNode),
      });
    }
  }
  const text = attributes
    .map((attribute) => {
      const key = attribute.oid_name ?? attribute.oid;
      return `${key}=${attribute.value}`;
    })
    .join(", ");
  return { text, attributes };
};

const validityTime = (node: DerNode): string => {
  if (node.tag !== 0x17 && node.tag !== 0x18)
    return fail("Validity instant is not UTCTime or GeneralizedTime.");
  return decodePrintable(node);
};

export interface ParsedCertificate {
  readonly start: number;
  readonly end: number;
  readonly serial_hex: string;
  readonly issuer: ReturnType<typeof decodeName>;
  readonly subject: ReturnType<typeof decodeName>;
  readonly not_before: string;
  readonly not_after: string;
  readonly signature_algorithm_oid: string;
}

/** Decode one X.509 Certificate SEQUENCE at a known file-relative DER node. */
export const parseCertificate = (node: DerNode): ParsedCertificate => {
  const children = sequence(node, "Certificate");
  const tbs = children[0];
  const signatureAlgorithm = children[1];
  if (tbs === undefined || signatureAlgorithm === undefined)
    return fail("Certificate is missing TBSCertificate or signatureAlgorithm.");
  const tbsChildren = sequence(tbs, "TBSCertificate");
  let index = 0;
  if (tbsChildren[0]?.tag === 0xa0) index = 1;
  const serial = tbsChildren[index];
  const issuer = tbsChildren[index + 2];
  const validity = tbsChildren[index + 3];
  const subject = tbsChildren[index + 4];
  if (
    serial === undefined ||
    serial.tag !== 0x02 ||
    issuer === undefined ||
    validity === undefined ||
    subject === undefined
  )
    return fail(
      "TBSCertificate is missing serial, issuer, validity, or subject.",
    );
  const validityChildren = sequence(validity, "Validity");
  const notBefore = validityChildren[0];
  const notAfter = validityChildren[1];
  if (notBefore === undefined || notAfter === undefined)
    return fail("Validity is missing notBefore or notAfter.");
  return {
    start: node.start,
    end: node.end,
    serial_hex: integerHex(serial.content),
    issuer: decodeName(issuer),
    subject: decodeName(subject),
    not_before: validityTime(notBefore),
    not_after: validityTime(notAfter),
    signature_algorithm_oid: algorithmOid(signatureAlgorithm),
  };
};

export interface ParsedSigner {
  readonly digest_algorithm_oid: string;
  readonly signature_algorithm_oid: string;
  readonly issuer: ReturnType<typeof decodeName> | null;
  readonly serial_hex: string | null;
  readonly authenticated_attributes: boolean;
}

const parseSigner = (node: DerNode): ParsedSigner => {
  const children = sequence(node, "SignerInfo");
  const version = children[0];
  const sid = children[1];
  const digestAlg = children[2];
  if (version === undefined || version.tag !== 0x02)
    return fail("SignerInfo is missing version.");
  if (sid === undefined || digestAlg === undefined)
    return fail("SignerInfo is missing sid or digestAlgorithm.");
  let issuer = null;
  let serial_hex: string | null = null;
  if (sid.tag === 0x30) {
    const name = sid.children[0];
    const serial = sid.children[1];
    if (name !== undefined && serial !== undefined && serial.tag === 0x02) {
      issuer = decodeName(name);
      serial_hex = integerHex(serial.content);
    }
  }
  let cursor = 3;
  const authenticated = children[cursor]?.tag === 0xa0;
  if (authenticated) cursor += 1;
  const signatureAlg = children[cursor];
  if (signatureAlg === undefined)
    return fail("SignerInfo is missing signatureAlgorithm.");
  return {
    digest_algorithm_oid: algorithmOid(digestAlg),
    signature_algorithm_oid: algorithmOid(signatureAlg),
    issuer,
    serial_hex,
    authenticated_attributes: authenticated,
  };
};

export interface ParsedSignedData {
  readonly content_type_oid: string;
  readonly digest_algorithm_oids: readonly string[];
  readonly certificates: readonly ParsedCertificate[];
  readonly signers: readonly ParsedSigner[];
}

const parseSignedData = (node: DerNode): ParsedSignedData => {
  const children = sequence(node, "SignedData");
  const digestSet = children[1];
  if (digestSet === undefined || digestSet.tag !== 0x31)
    return fail("SignedData is missing digestAlgorithms.");
  const digest_algorithm_oids = digestSet.children.map(algorithmOid);
  const certificates: ParsedCertificate[] = [];
  const signers: ParsedSigner[] = [];
  for (const child of children.slice(3)) {
    if (child.tag === 0xa0)
      for (const certificate of child.children)
        certificates.push(parseCertificate(certificate));
    else if (child.tag === 0x31)
      for (const signer of child.children) signers.push(parseSigner(signer));
  }
  return {
    content_type_oid: "1.2.840.113549.1.7.2",
    digest_algorithm_oids,
    certificates,
    signers,
  };
};

/** Decode ContentInfo wrapping SignedData; other content types remain unsupported. */
export const parsePkcs7SignedData = (bytes: Buffer): ParsedSignedData => {
  const root = readDer(bytes);
  const children = sequence(root, "ContentInfo");
  const type = children[0];
  const content = children[1];
  if (type === undefined || type.tag !== 0x06)
    return fail("ContentInfo is missing contentType.");
  const oid = decodeOid(type.content);
  if (oid !== "1.2.840.113549.1.7.2")
    return fail(`PKCS#7 contentType ${oid} is not signedData.`);
  const signedData = content?.children[0];
  if (content === undefined || content.tag !== 0xa0 || signedData === undefined)
    return fail("signedData content is missing.");
  return parseSignedData(signedData);
};

import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";

import {
  CompanyFileValidationError,
  MAX_COMPANY_FILE_BINARY_BYTES,
  MAX_COMPANY_FILE_BYTES,
  MAX_COMPANY_FILE_DESCRIPTION_BYTES,
  parseCompanyFileInput,
} from "../src/ingest/company-file.js";

// Minimal valid one-page PDF whose single text item reads "Hello HaloMem PDF".
const PDF_WITH_TEXT = Buffer.from(
  "JVBERi0xLjQKMSAwIG9iago8PC9UeXBlL0NhdGFsb2cvUGFnZXMgMiAwIFI+PgplbmRvYmoKMiAwIG9iago8PC9UeXBlL1BhZ2VzL0tpZHNbMyAwIFJdL0NvdW50IDE+PgplbmRvYmoKMyAwIG9iago8PC9UeXBlL1BhZ2UvUGFyZW50IDIgMCBSL01lZGlhQm94WzAgMCA2MTIgNzkyXS9SZXNvdXJjZXM8PC9Gb250PDwvRjEgNCAwIFI+Pj4+L0NvbnRlbnRzIDUgMCBSPj4KZW5kb2JqCjQgMCBvYmoKPDwvVHlwZS9Gb250L1N1YnR5cGUvVHlwZTEvQmFzZUZvbnQvSGVsdmV0aWNhPj4KZW5kb2JqCjUgMCBvYmoKPDwvTGVuZ3RoIDQ4Pj5zdHJlYW0KQlQgL0YxIDI0IFRmIDcyIDcyMCBUZCAoSGVsbG8gSGFsb01lbSBQREYpIFRqIEVUCmVuZHN0cmVhbQplbmRvYmoKeHJlZgowIDYKMDAwMDAwMDAwMCA2NTUzNSBmIAowMDAwMDAwMDA5IDAwMDAwIG4gCjAwMDAwMDAwNTQgMDAwMDAgbiAKMDAwMDAwMDEwNSAwMDAwMCBuIAowMDAwMDAwMjE3IDAwMDAwIG4gCjAwMDAwMDAyODAgMDAwMDAgbiAKdHJhaWxlcgo8PC9TaXplIDYvUm9vdCAxIDAgUj4+CnN0YXJ0eHJlZgozNzUKJSVFT0YK",
  "base64",
);
// Same document with an empty content stream: valid PDF, no text layer.
const PDF_WITHOUT_TEXT = Buffer.from(
  "JVBERi0xLjQKMSAwIG9iago8PC9UeXBlL0NhdGFsb2cvUGFnZXMgMiAwIFI+PgplbmRvYmoKMiAwIG9iago8PC9UeXBlL1BhZ2VzL0tpZHNbMyAwIFJdL0NvdW50IDE+PgplbmRvYmoKMyAwIG9iago8PC9UeXBlL1BhZ2UvUGFyZW50IDIgMCBSL01lZGlhQm94WzAgMCA2MTIgNzkyXS9SZXNvdXJjZXM8PC9Gb250PDwvRjEgNCAwIFI+Pj4+L0NvbnRlbnRzIDUgMCBSPj4KZW5kb2JqCjQgMCBvYmoKPDwvVHlwZS9Gb250L1N1YnR5cGUvVHlwZTEvQmFzZUZvbnQvSGVsdmV0aWNhPj4KZW5kb2JqCjUgMCBvYmoKPDwvTGVuZ3RoIDA+PnN0cmVhbQoKZW5kc3RyZWFtCmVuZG9iagp4cmVmCjAgNgowMDAwMDAwMDAwIDY1NTM1IGYgCjAwMDAwMDAwMDkgMDAwMDAgbiAKMDAwMDAwMDA1NCAwMDAwMCBuIAowMDAwMDAwMTA1IDAwMDAwIG4gCjAwMDAwMDAyMTcgMDAwMDAgbiAKMDAwMDAwMDI4MCAwMDAwMCBuIAp0cmFpbGVyCjw8L1NpemUgNi9Sb290IDEgMCBSPj4Kc3RhcnR4cmVmCjMyNgolJUVPRgo=",
  "base64",
);
// Minimal valid DOCX whose paragraph reads "Hello HaloMem Word".
const DOCX_WITH_TEXT = Buffer.from(
  "UEsDBBQAAAAIABwPEl15bjPX6AAAAK0BAAATAAAAW0NvbnRlbnRfVHlwZXNdLnhtbH1QyU7DMBD9FWuuKHHggBCK0wPLETiUDxjZk8SqN3nc0v49Tlt6QIXjzFv1+tXeO7GjzDYGBbdtB4KCjsaGScHn+rV5AMEFg0EXAyk4EMNq6NeHRCyqNrCCuZT0KCXrmTxyGxOFiowxeyz1zJNMqDc4kbzrunupYygUSlMWDxj6Zxpx64p42df3qUcmxyCeTsQlSwGm5KzGUnG5C+ZXSnNOaKvyyOHZJr6pBJBXExbk74Cz7r0Ok60h8YG5vKGvLPkVs5Em6q2vyvZ/mys94zhaTRf94pZy1MRcF/euvSAebfjpL49zD99QSwMEFAAAAAgAHA8SXZv9N+qtAAAAKQEAAAsAAABfcmVscy8ucmVsc43POw7CMAwG4KtE3mlaBoRQ0y4IqSsqB7ASN61oHkrCo7cnAwNFDIy2f3+W6/ZpZnanECdnBVRFCYysdGqyWsClP232wGJCq3B2lgQsFKFt6jPNmPJKHCcfWTZsFDCm5A+cRzmSwVg4TzZPBhcMplwGzT3KK2ri27Lc8fBpwNpknRIQOlUB6xdP/9huGCZJRydvhmz6ceIrkWUMmpKAhwuKq3e7yCzwpuarF5sXUEsDBBQAAAAIABwPEl0r0veZowAAANsAAAARAAAAd29yZC9kb2N1bWVudC54bWxFjsEOwiAMhl+FcHdMD8YsY7uZXbxpPCPUbQm0BNC5txfmwcvX9G/6tW3/cZa9IcSZUPJ9VXMGqMnMOEp+u553J85iUmiUJQTJV4i879qlMaRfDjCxLMDYLJJPKflGiKgncCpW5AHz7EnBqZTbMIqFgvGBNMSY/c6KQ10fhVMz8qJ8kFlL9QWhIHUDWEtsyNcv4Ng9C1pR8sKw0W/87Yr/X90XUEsBAhQDFAAAAAgAHA8SXXluM9foAAAArQEAABMAAAAAAAAAAAAAAIABAAAAAFtDb250ZW50X1R5cGVzXS54bWxQSwECFAMUAAAACAAcDxJdm/036q0AAAApAQAACwAAAAAAAAAAAAAAgAEZAQAAX3JlbHMvLnJlbHNQSwECFAMUAAAACAAcDxJdK9L3maMAAADbAAAAEQAAAAAAAAAAAAAAgAHvAQAAd29yZC9kb2N1bWVudC54bWxQSwUGAAAAAAMAAwC5AAAAwQIAAAAA",
  "base64",
);

function input(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    fileName: "handbook.md",
    content: Buffer.from("# Handbook\n\nEscalate urgent incidents to the on-call lead."),
    purpose: "Give support agents the approved escalation process",
    description: "Current support operating handbook",
    businessFunction: "Customer support",
    dataSensitive: false,
    ...overrides,
  };
}

describe("company file input boundary", () => {
  it.each([
    ["notes.txt", "Plain organizational knowledge."],
    ["notes.md", "# Organizational knowledge"],
    ["notes.markdown", "# Organizational knowledge"],
    ["records.csv", "id,value\n1,alpha"],
    ["records.json", '{"id":1,"value":"alpha"}'],
    ["records.yaml", "id: 1\nvalue: alpha"],
    ["records.yml", "- id: 1\n  value: alpha"],
  ])("accepts bounded UTF-8 %s input", async (fileName, content) => {
    const records = await parseCompanyFileInput(input({
      fileName,
      content: Buffer.from(content),
      dataSensitive: true,
    }));

    expect(records).toEqual([expect.objectContaining({
      docId: fileName,
      scope: "org",
      verbatim: false,
      classification: { sensitivity: "confidential" },
    })]);
    expect(records[0]!.content).toContain(content);
    expect(records[0]!.content).toContain('"purpose":"Give support agents the approved escalation process"');
    expect(records[0]!.content).toContain('"businessFunction":"Customer support"');
  });

  it("accepts the exact byte limit and rejects one byte more", async () => {
    const records = await parseCompanyFileInput(input({
      fileName: "limit.txt",
      content: Buffer.alloc(MAX_COMPANY_FILE_BYTES, 0x61),
    }));
    expect(records.length).toBeGreaterThan(1);
    expect(records[0]?.docId).toMatch(/^limit\.txt#chunk-0001-of-/);

    await expect(parseCompanyFileInput(input({
      fileName: "too-large.txt",
      content: Buffer.alloc(MAX_COMPANY_FILE_BYTES + 1, 0x61),
    }))).rejects.toThrow(/512 KiB limit/i);
  });

  it("rejects invalid UTF-8, UTF-16 text, empty text, and binary control characters", async () => {
    await expect(parseCompanyFileInput(input({
      fileName: "invalid.txt",
      content: Buffer.from([0xc3, 0x28]),
    }))).rejects.toThrow(/valid UTF-8/i);
    // UTF-16LE bytes are not valid UTF-8 text and must be rejected, never
    // silently transcoded into mojibake.
    await expect(parseCompanyFileInput(input({
      fileName: "utf16.txt",
      content: Buffer.from("plain ascii text", "utf16le"),
    }))).rejects.toThrow(/valid UTF-8|control characters/i);
    await expect(parseCompanyFileInput(input({ content: Buffer.from(" \n\t ") }))).rejects.toThrow(/cannot be empty/i);
    await expect(parseCompanyFileInput(input({ content: Buffer.from("safe\u0000hidden") }))).rejects.toThrow(/control characters/i);
    await expect(parseCompanyFileInput(input({ content: Buffer.alloc(0) }))).rejects.toThrow(/cannot be empty/i);
  });

  it("rejects unsafe filenames and unsupported formats", async () => {
    for (const fileName of ["../secret.txt", "folder\\secret.md", "bad\u0000name.txt"]) {
      await expect(parseCompanyFileInput(input({ fileName }))).rejects.toThrow(/filename/i);
    }
    await expect(parseCompanyFileInput(input({ fileName: "report.doc" }))).rejects.toThrow(/unsupported company file format/i);
    await expect(parseCompanyFileInput(input({ fileName: "photo.png" }))).rejects.toThrow(/unsupported company file format/i);
  });

  it("rejects structured content that does not match its extension", async () => {
    await expect(parseCompanyFileInput(input({
      fileName: "records.json",
      content: Buffer.from("not-json"),
    }))).rejects.toThrow(/does not contain valid JSON/i);
    await expect(parseCompanyFileInput(input({
      fileName: "records.json",
      content: Buffer.from('"a scalar"'),
    }))).rejects.toThrow(/JSON object or array/i);
    await expect(parseCompanyFileInput(input({
      fileName: "records.yaml",
      content: Buffer.from("items: ["),
    }))).rejects.toThrow(/does not contain valid YAML/i);
    await expect(parseCompanyFileInput(input({
      fileName: "records.csv",
      content: Buffer.from("this is not a table"),
    }))).rejects.toThrow(/does not contain a CSV table/i);
  });

  it("requires bounded purpose, business function, description, and an explicit sensitivity choice", async () => {
    await expect(parseCompanyFileInput(input({ purpose: "  " }))).rejects.toThrow(/purpose is required/i);
    await expect(parseCompanyFileInput(input({ businessFunction: "Finance\nAdmin" }))).rejects.toThrow(/businessFunction.*control/i);
    await expect(parseCompanyFileInput(input({
      description: "a".repeat(MAX_COMPANY_FILE_DESCRIPTION_BYTES + 1),
    }))).rejects.toThrow(/description.*limit/i);
    const withoutSensitivity = input();
    delete withoutSensitivity.dataSensitive;
    await expect(parseCompanyFileInput(withoutSensitivity)).rejects.toThrow(/dataSensitive must be explicitly true or false/i);
    await expect(parseCompanyFileInput(input({ dataSensitive: "false" }))).rejects.toThrow(/dataSensitive must be explicitly true or false/i);
  });

  it("rejects caller-owned authority fields and unknown metadata", async () => {
    for (const field of ["namespace", "actor", "uploadedBy", "scope", "sourceAccess", "acl", "role"]) {
      await expect(parseCompanyFileInput(input({ [field]: "forged" }))).rejects.toThrow(/caller-owned authority field/i);
    }
    await expect(parseCompanyFileInput(input({ unexpected: "value" }))).rejects.toThrow(/unknown company file field/i);
  });

  it("treats hostile metadata as deterministic text rather than executable structure", async () => {
    const hostile = input({
      purpose: "Support <script>alert(1)</script>",
      description: '</script><img src=x onerror="alert(1)">',
      businessFunction: "__proto__",
    });

    const first = await parseCompanyFileInput(hostile);
    const second = await parseCompanyFileInput(hostile);

    expect(first).toEqual(second);
    const [metadataLine] = first[0]!.content.split("\n");
    const metadata = JSON.parse(metadataLine!.slice("[company-file] ".length));
    expect(metadata).toEqual({
      purpose: "Support <script>alert(1)</script>",
      description: '</script><img src=x onerror="alert(1)">',
      businessFunction: "__proto__",
      dataSensitive: false,
    });
  });

  it("throws one stable validation error type", async () => {
    await expect(parseCompanyFileInput(null)).rejects.toThrow(CompanyFileValidationError);
  });
});

describe("company file binary formats", () => {
  it("extracts text from a valid PDF into the standard record contract", async () => {
    const records = await parseCompanyFileInput(input({
      fileName: "runbook.pdf",
      content: PDF_WITH_TEXT,
    }));

    expect(records).toHaveLength(1);
    expect(records[0]!.docId).toBe("runbook.pdf");
    expect(records[0]!.content).toContain("Hello HaloMem PDF");
    expect(records[0]!.content).toContain("[company-file]");
  });

  it("extracts text from a valid Word document into the standard record contract", async () => {
    const records = await parseCompanyFileInput(input({
      fileName: "runbook.docx",
      content: DOCX_WITH_TEXT,
    }));

    expect(records).toHaveLength(1);
    expect(records[0]!.docId).toBe("runbook.docx");
    expect(records[0]!.content).toContain("Hello HaloMem Word");
  });

  it("rejects content that does not match its binary extension", async () => {
    await expect(parseCompanyFileInput(input({
      fileName: "fake.pdf",
      content: Buffer.from("plain text wearing a pdf name"),
    }))).rejects.toThrow(/does not match its \.pdf extension/i);
    await expect(parseCompanyFileInput(input({
      fileName: "fake.docx",
      content: PDF_WITH_TEXT,
    }))).rejects.toThrow(/does not match its \.docx extension/i);
  });

  it("rejects corrupt binary documents with a format-specific reason", async () => {
    const corruptPdf = Buffer.concat([PDF_WITH_TEXT.subarray(0, 40), Buffer.from("garbage")]);
    await expect(parseCompanyFileInput(input({
      fileName: "corrupt.pdf",
      content: corruptPdf,
    }))).rejects.toThrow(/not a valid PDF|does not match its \.pdf extension/i);
    const corruptDocx = Buffer.concat([Buffer.from("PK"), Buffer.alloc(64, 0x41)]);
    await expect(parseCompanyFileInput(input({
      fileName: "corrupt.docx",
      content: corruptDocx,
    }))).rejects.toThrow(/does not match its \.docx extension|not a valid Word document/i);
  });

  it("rejects a valid PDF that has no text layer", async () => {
    await expect(parseCompanyFileInput(input({
      fileName: "scanned.pdf",
      content: PDF_WITHOUT_TEXT,
    }))).rejects.toThrow(/no extractable text/i);
  });

  it("rejects empty and oversized binary documents", async () => {
    await expect(parseCompanyFileInput(input({
      fileName: "empty.pdf",
      content: Buffer.alloc(0),
    }))).rejects.toThrow(/cannot be empty/i);
    await expect(parseCompanyFileInput(input({
      fileName: "huge.pdf",
      content: Buffer.alloc(MAX_COMPANY_FILE_BINARY_BYTES + 1, 0x61),
    }))).rejects.toThrow(/5 MiB limit/i);
    // A 600 KiB PDF is fine even though text formats cap at 512 KiB.
    const bigPdf = Buffer.concat([PDF_WITH_TEXT, Buffer.alloc(600 * 1024, 0x20)]);
    await expect(parseCompanyFileInput(input({
      fileName: "big.pdf",
      content: bigPdf,
    }))).resolves.toHaveLength(1);
  });
});

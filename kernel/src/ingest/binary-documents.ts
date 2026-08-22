import { Buffer } from "node:buffer";

/**
 * Binary company-document (PDF / DOCX) text extraction.
 *
 * This boundary is the binary sibling of the text decoding in
 * company-file.ts: it receives the caller's original bytes, proves the bytes
 * match the claimed extension (magic bytes + container markers), extracts
 * text, and rejects with a specific reason for every failure rung. No OCR:
 * a document with no text layer yields "no extractable text".
 */

const PDF_MAGIC = "%PDF-";
const ZIP_MAGIC = 0x04034b50; // "PK\x03\x04"
const DOCX_DOCUMENT_PART = "word/document.xml";

export class BinaryDocumentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BinaryDocumentError";
  }
}

function startsWithAscii(bytes: Uint8Array, marker: string): boolean {
  if (bytes.byteLength < marker.length) return false;
  for (let index = 0; index < marker.length; index += 1) {
    if (bytes[index] !== marker.charCodeAt(index)) return false;
  }
  return true;
}

function containsAscii(bytes: Uint8Array, marker: string): boolean {
  outer: for (let index = 0; index + marker.length <= bytes.byteLength; index += 1) {
    for (let offset = 0; offset < marker.length; offset += 1) {
      if (bytes[index + offset] !== marker.charCodeAt(offset)) continue outer;
    }
    return true;
  }
  return false;
}

async function extractPdfText(bytes: Uint8Array): Promise<string> {
  if (!startsWithAscii(bytes, PDF_MAGIC)) {
    throw new BinaryDocumentError("file content does not match its .pdf extension");
  }
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.mjs");
  // pdfjs-dist may transfer/detach the ArrayBuffer it receives. Give it an
  // owned copy so parsing cannot zero the authoritative upload bytes before
  // provenance and file metadata are reserved by the caller.
  const data = Uint8Array.from(bytes);
  const loadingTask = pdfjs.getDocument({ data, useSystemFonts: true });
  let document;
  try {
    document = await loadingTask.promise;
  } catch (error) {
    const name = error instanceof Error ? error.name : "";
    if (name === "PasswordException") {
      throw new BinaryDocumentError("password-protected PDFs are not supported");
    }
    throw new BinaryDocumentError("company .pdf file is not a valid PDF document");
  }
  try {
    const pages: string[] = [];
    for (let pageNumber = 1; pageNumber <= document.numPages; pageNumber += 1) {
      const page = await document.getPage(pageNumber);
      const text = await page.getTextContent();
      const items = (text.items as Array<{ str?: unknown }>)
        .map((item) => (typeof item.str === "string" ? item.str : ""))
        .filter((chunk) => chunk.length > 0);
      pages.push(items.join(" "));
    }
    return pages.join("\n\n");
  } catch {
    throw new BinaryDocumentError("company .pdf file is not a valid PDF document");
  } finally {
    await loadingTask.destroy().catch(() => undefined);
  }
}

async function extractDocxText(bytes: Uint8Array): Promise<string> {
  const zipMagic = bytes.byteLength >= 4
    ? (bytes[0]! | (bytes[1]! << 8) | (bytes[2]! << 16) | (bytes[3]! << 24)) >>> 0
    : 0;
  if (zipMagic !== ZIP_MAGIC || !containsAscii(bytes, DOCX_DOCUMENT_PART)) {
    throw new BinaryDocumentError("file content does not match its .docx extension");
  }
  const mammoth = await import("mammoth");
  let result: { value: string };
  try {
    result = await mammoth.extractRawText({ buffer: Buffer.from(bytes) });
  } catch {
    throw new BinaryDocumentError("company .docx file is not a valid Word document");
  }
  return result.value;
}

/**
 * Extract text from a binary company document. Throws BinaryDocumentError
 * with a specific reason for mismatched content, encryption, corrupt
 * structure, and documents with no text layer.
 */
export async function extractBinaryDocumentText(
  extension: string,
  bytes: Uint8Array,
): Promise<string> {
  const text = extension === ".pdf"
    ? await extractPdfText(bytes)
    : await extractDocxText(bytes);
  if (text.trim().length === 0) {
    throw new BinaryDocumentError(
      extension === ".pdf"
        ? "company .pdf file contains no extractable text"
        : "company .docx file contains no extractable text",
    );
  }
  return text;
}

export function isBinaryCompanyExtension(extension: string): boolean {
  return extension === ".pdf" || extension === ".docx";
}

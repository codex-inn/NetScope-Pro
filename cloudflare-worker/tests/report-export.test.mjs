import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { createPdfBytes } = require("../../report-export.js");

test("builds a valid single-page PDF report with escaped text", () => {
  const bytes = createPdfBytes("Authorized assessment (test)", ["Header: value", "Fix: use (secure) policy"]);
  const pdf = new TextDecoder().decode(bytes);
  assert.ok(pdf.startsWith("%PDF-1.4"));
  assert.ok(pdf.includes("/Type /Catalog"));
  assert.ok(pdf.includes("Authorized assessment \\(test\\)"));
  const xref = Number(pdf.match(/startxref\n(\d+)/)?.[1]);
  assert.ok(Number.isInteger(xref));
  assert.equal(pdf.slice(xref, xref + 4), "xref");
});

test("splits long reports across pages and preserves xref offsets", () => {
  const bytes = createPdfBytes("Assessment", Array.from({ length: 140 }, (_, i) => "Finding " + i + " ".repeat(90) + "(review)"));
  const pdf = new TextDecoder().decode(bytes);
  assert.ok((pdf.match(/\/Type \/Page \/Parent/g) || []).length >= 3);
  const xrefAt = Number(pdf.match(/startxref\n(\d+)/)?.[1]);
  const xrefText = pdf.slice(xrefAt).split("\n");
  const entries = xrefText.slice(2, -4).filter(line => /\d{10} 00000 n/.test(line));
  assert.ok(entries.length >= 9);
  for (const entry of entries) {
    const offset = Number(entry.slice(0, 10));
    assert.match(pdf.slice(offset, offset + 8), /^\d+ 0 obj/);
  }
});


(function (root, factory) {
  const api = factory();
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.NetScopeReport = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";
  function createPdfBytes(title, sourceLines) {
    const safe = value => String(value ?? "").replace(/[^\x20-\x7E]/g, "?");
    const wrap = line => {
      const words = safe(line).split(/\s+/), out = [];
      let current = "";
      for (const word of words) {
        if (!word) continue;
        if ((current + " " + word).trim().length > 92 && current) {
          out.push(current);
          current = word.slice(0, 92);
          let rest = word.slice(92);
          while (rest) { out.push(current); current = rest.slice(0, 92); rest = rest.slice(92); }
        } else current = (current + " " + word).trim();
      }
      if (current) out.push(current);
      return out.length ? out : [""];
    };
    const lines = [safe(title), "=".repeat(Math.min(72, safe(title).length)), "", ...sourceLines.flatMap(wrap)];
    const pages = [];
    for (let i = 0; i < lines.length; i += 50) pages.push(lines.slice(i, i + 50));
    const objects = [];
    const pageIds = pages.map((_, index) => 4 + index * 2);
    objects.push("<< /Type /Catalog /Pages 2 0 R >>");
    objects.push("<< /Type /Pages /Kids [" + pageIds.map(id => id + " 0 R").join(" ") + "] /Count " + pages.length + " >>");
    objects.push("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>");
    for (let i = 0; i < pages.length; i++) {
      const pageId = 4 + i * 2, streamId = pageId + 1;
      const commands = ["BT", "/F1 9 Tf", "50 790 Td", "13 TL"];
      for (const line of pages[i]) {
        const escaped = line.replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
        commands.push("(" + escaped + ") Tj", "T*");
      }
      commands.push("ET");
      const stream = commands.join("\n");
      objects.push("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 3 0 R >> >> /Contents " + streamId + " 0 R >>");
      objects.push("<< /Length " + stream.length + " >>\nstream\n" + stream + "\nendstream");
    }
    let pdf = "%PDF-1.4\n%NetScope Pro report\n";
    const offsets = [0];
    objects.forEach((object, index) => {
      offsets.push(pdf.length);
      pdf += (index + 1) + " 0 obj\n" + object + "\nendobj\n";
    });
    const xref = pdf.length;
    pdf += "xref\n0 " + (objects.length + 1) + "\n0000000000 65535 f \n";
    for (const offset of offsets.slice(1)) pdf += String(offset).padStart(10, "0") + " 00000 n \n";
    pdf += "trailer\n<< /Size " + (objects.length + 1) + " /Root 1 0 R >>\nstartxref\n" + xref + "\n%%EOF\n";
    return new TextEncoder().encode(pdf);
  }
  return { createPdfBytes };
});


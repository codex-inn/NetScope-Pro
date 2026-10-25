# 🛡️ NetScope-Pro

A browser-based network and website inspection toolkit with optional local Windows scanning.

🌐 **Live website:** https://codex-inn.github.io/NetScope-Pro/

## ✨ Features

- 🔎 URL and DNS inspection, including a DNSSEC authentication signal
- 🧭 Website security checks for configured, authorized targets
- 📡 Optional Windows Wi-Fi and private-LAN discovery
- 📊 Findings, scan history, comparison, and JSON/CSV/PDF reports
- ☁️ Optional Cloudflare Worker for bounded public HTTP/TCP checks

## 🚀 Getting Started

- **Browser-only:** Open the [live website](https://codex-inn.github.io/NetScope-Pro/). No installer is required for browser-based tools.
- **Windows Wi-Fi/LAN scanner:** Requires the local Python API running on your Windows PC. Follow the [Local Scanner Quickstart](docs/LOCAL-SCANNER-QUICKSTART.md).
- **Public website checks:** Require the optional Cloudflare Worker to be deployed and configured. A displayed Worker URL alone does not confirm it is operational.

## 🔐 Safety & Limitations

- Scan only systems and networks you own or have explicit permission to test.
- Configure exact authorized targets; do not use wildcard or unauthorized targets.
- GitHub Pages alone cannot access your laptop's Wi-Fi adapter or scan your private LAN.
- Keep the local API bound to `127.0.0.1`; do not expose it directly to the internet.
- Findings are indicators for review, not proof of a confirmed vulnerability.

## 🧪 Tests

```bash
pytest -q
node --test cloudflare-worker/tests/*.test.mjs
```

Some tests use mocked network responses; passing tests do not replace real-world feature verification.

---
💡 Built for authorized network visibility and security learning.

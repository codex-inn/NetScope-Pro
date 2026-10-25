from pathlib import Path


def test_hosted_dns_inspector_requests_dnssec_validation_signal():
    html = (Path(__file__).resolve().parents[1] / "index.html").read_text(encoding="utf-8")
    assert "async function dnsQuery(name,type,dnssec=false)" in html
    assert "(dnssec?'&do=1':'')" in html
    assert 'dnssec.authenticated=d.AD===true' in html
    assert 'title:"DNSSEC validation not confirmed"' in html
    assert 'dnssec,spf,dmarc,dkim,findings' in html


def test_network_tools_open_local_scanner_without_broadening_api_access():
    html = (Path(__file__).resolve().parents[1] / "index.html").read_text(encoding="utf-8")
    assert 'href="http://127.0.0.1:8765/workspace#section-wifi"' in html
    assert 'docs/LOCAL-SCANNER-QUICKSTART.md' in html
    # The UI documents the local-service boundary instead of adding cross-origin API access.
    assert "local Python service—not GitHub Pages" in html

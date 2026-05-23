"""Regression tests for the false positives discovered when scanning a
real Grafana checkout under ~/Documents/Coding.

Two patterns were producing critical/high noise in v0.1.2:

  1. secrets/private_key_block fired on any HTML/TSX file that contained
     the literal string "-----BEGIN ... PRIVATE KEY-----" as a label or
     placeholder, with no actual PEM body.
  2. obfuscation/obfuscated_loader fired on minified vendor bundles such
     as Monaco editor JS files that legitimately contain long lines,
     eval(), and Function() calls.

Both heuristics are now context-aware. These tests pin the new behavior.
"""

from __future__ import annotations

from pathlib import Path

from aegis.core.constitution import load
from aegis.core.index import Index
from aegis.core.journal import Journal
from aegis.core.policy import PolicyEngine
from aegis.core.runner import run_scan


REPO = Path(__file__).resolve().parents[1]


def _bootstrap(tmp_path: Path) -> tuple[PolicyEngine, Index]:
    charter = load(REPO / "data" / "mythos.yaml")
    journal = Journal(root=tmp_path / "journal")
    policy = PolicyEngine(constitution=charter, journal=journal)
    index = Index(db_path=tmp_path / "idx.sqlite")
    return policy, index


def test_private_key_block_does_not_fire_on_pem_label_in_template(tmp_path: Path) -> None:
    sample = tmp_path / "tls_settings.html"
    sample.write_text(
        '<textarea placeholder="-----BEGIN CERTIFICATE-----\n'
        '...\n'
        '-----END CERTIFICATE-----"></textarea>\n'
        '<p>Paste your PEM, e.g. "-----BEGIN RSA PRIVATE KEY-----" header.</p>\n',
        encoding="utf-8",
    )
    policy, index = _bootstrap(tmp_path)
    run_scan(root=tmp_path, index=index, policy=policy)
    rows = list(index.findings(scanner="secrets"))
    assert all(r["rule"] != "private_key_block" for r in rows), (
        f"private_key_block should not fire on label-only content; got {rows!r}"
    )


def test_private_key_block_still_fires_on_real_pem(tmp_path: Path) -> None:
    sample = tmp_path / "leaked.pem"
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDA" * 4
    sample.write_text(
        "-----BEGIN RSA PRIVATE KEY-----\n"
        + body + "\n"
        "-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    policy, index = _bootstrap(tmp_path)
    run_scan(root=tmp_path, index=index, policy=policy)
    rows = list(index.findings(scanner="secrets"))
    assert any(r["rule"] == "private_key_block" for r in rows), (
        f"real PEM body must still be detected; got {rows!r}"
    )


def test_obfuscation_skips_minified_bundle(tmp_path: Path) -> None:
    pkg = tmp_path / "vendor" / "monaco-editor" / "min" / "vs"
    pkg.mkdir(parents=True)
    junk = pkg / "editor.main.js"
    long_line = "var x = " + ",".join(f"new Function('return {i}')" for i in range(200))
    junk.write_text(long_line + ";\n", encoding="utf-8")
    policy, index = _bootstrap(tmp_path)
    # Note: 'vendor' is in default excluded_dirs so we have to test against a
    # path that bypasses the exclusion. Place the bundle under a non-excluded
    # parent ('lib') but with 'min' as a path component.
    real_pkg = tmp_path / "lib" / "monaco" / "min" / "vs"
    real_pkg.mkdir(parents=True)
    target = real_pkg / "editor.main.js"
    target.write_text(long_line + ";\n", encoding="utf-8")
    # Also the .min.<ext> filename convention.
    (tmp_path / "lib" / "app.min.js").write_text(long_line + ";\n", encoding="utf-8")

    run_scan(root=tmp_path, index=index, policy=policy)
    rows = list(index.findings(scanner="obfuscation"))
    assert rows == [], (
        f"obfuscation should skip minified vendor bundles; got {rows!r}"
    )


def test_obfuscation_still_fires_on_real_packer(tmp_path: Path) -> None:
    sample = tmp_path / "loader.js"
    body_lines = []
    body_lines.append('"' + ('𒀱' * 20) + '";')
    payload = (
        "(()=>{"
        "if(process.execArgv.join('').includes('inspect')||process.env.NODE_OPTIONS?.includes('inspect'))process.exit(1);"
        "const fs=require('fs'),crypto=require('crypto'),zlib=require('zlib'),path=require('path');"
        "const blob=Buffer.from('AAAA','base64');"
        "const dec=crypto.createDecipheriv('aes-256-gcm', blob, blob);"
        "const out=zlib.gunzipSync(Buffer.concat([dec.update(blob)]));"
        "const tmp=path.join(process.cwd(),`.tmp_${Date.now()}_${process.pid}.js`);"
        "fs.writeFileSync(tmp,out);try{require(tmp)}finally{fs.unlinkSync(tmp)}"
        "})();"
    )
    body_lines.append(payload)
    body_lines.append('"' + (chr(0x4E00) * 20000) + '";')
    sample.write_text("\n".join(body_lines), encoding="utf-8")
    policy, index = _bootstrap(tmp_path)
    run_scan(root=tmp_path, index=index, policy=policy)
    rows = list(index.findings(scanner="obfuscation"))
    assert rows, "real packer must still trigger obfuscation scanner"

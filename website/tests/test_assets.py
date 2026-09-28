"""Offline-first and integrity checks over templates and static assets.
Pure file checks; no app import needed."""

import re
from pathlib import Path

WEB = Path(__file__).resolve().parent.parent
TEMPLATES = WEB / "templates"
STANDALONE = {"base.html", "login.html", "error.html", "account_setup.html"}
# Zero external hosts: all libraries are vendored under /static/vendor.
ALLOWED_HOSTS = set()


def _templates():
    return sorted(TEMPLATES.glob("*.html"))


def test_every_page_extends_base_or_is_standalone():
    for t in _templates():
        if t.name in STANDALONE:
            continue
        text = t.read_text()
        assert '{% extends "base.html" %}' in text, f"{t.name} must extend base.html"


def test_referenced_static_files_exist():
    ref = re.compile(r'/static/([A-Za-z0-9_./-]+)')
    for t in _templates():
        for rel in ref.findall(t.read_text()):
            assert (WEB / "static" / rel).exists(), f"{t.name} references missing /static/{rel}"


def test_no_external_resource_loads_outside_allowlist():
    # Only resource loads count: script src and stylesheet links. Plain <a href>
    # documentation links (e.g. to haveibeenpwned) are not resource loads.
    script_src = re.compile(r'<script[^>]*\ssrc\s*=\s*"https?://([A-Za-z0-9.\-]+)')
    link_css = re.compile(r'<link[^>]*\shref\s*=\s*"https?://([A-Za-z0-9.\-]+)')
    for t in _templates():
        text = t.read_text()
        for m in list(script_src.finditer(text)) + list(link_css.finditer(text)):
            assert m.group(1) in ALLOWED_HOSTS, f"{t.name} loads from disallowed host {m.group(1)}"


def test_vendored_libs_present():
    vendor = WEB / "static" / "vendor"
    for f in ("chart.umd.min.js", "cytoscape.min.js", "marked.min.js", "prism.min.js"):
        assert (vendor / f).exists() and (vendor / f).stat().st_size > 0, f"missing vendored {f}"


def test_hud_exposes_shared_helpers():
    hud = (WEB / "static" / "js" / "hud.js").read_text()
    assert "function fetchJSON" in hud
    assert "function emptyState" in hud
    # exported on window.HUD so pages can call HUD.fetchJSON / HUD.emptyState
    assert "fetchJSON: fetchJSON" in hud
    assert "emptyState: emptyState" in hud


def test_pages_route_data_loads_through_hud():
    # Migrated pages use HUD.fetchJSON and no longer ship their own toast-container
    # DOM implementation (they delegate to HUD.toast).
    js = WEB / "static" / "js"
    for name in ("iocs.js", "reports.js", "cases.js", "dashboard.js", "settings.js"):
        text = (js / name).read_text()
        assert "HUD.fetchJSON" in text, f"{name} should use HUD.fetchJSON"
        assert 'getElementById("toast-container")' not in text, \
            f"{name} should not reimplement the toast container"


def test_world_geojson_present_and_valid():
    import json
    p = WEB / "static" / "data" / "world.geojson"
    assert p.exists(), "bundled world.geojson missing"
    data = json.loads(p.read_text())
    assert data.get("type") == "FeatureCollection"
    assert len(data["features"]) > 100
    assert all("iso" in f["properties"] for f in data["features"])

from pathlib import Path
import re
import shutil
import subprocess
import pytest
from fastapi.testclient import TestClient

import api


@pytest.fixture
def client():
    return TestClient(api.app)


def test_index_contains_banner_text(client):
    r = client.get("/")
    assert r.status_code == 200
    expected_banner = "Plausible access paths under a simplified IAM model. Explicit Deny, Conditions, permission boundaries and SCPs are not evaluated."
    assert expected_banner in r.text


def test_static_urls_in_index_return_200(client):
    r = client.get("/")
    assert r.status_code == 200
    html = r.text

    # Extract all /static/... references
    urls = re.findall(r'[\'"](/static/[^\'"]+)[\'"]', html)
    assert len(urls) >= 3  # vis-network.css, style.css, vis-network.min.js, app.js
    for u in urls:
        res = client.get(u)
        assert res.status_code == 200, f"Failed to fetch static asset: {u}"


def test_no_inner_html_in_frontend():
    frontend_dir = Path("frontend")
    for f in frontend_dir.glob("**/*"):
        if f.suffix in (".html", ".js"):
            content = f.read_text(encoding="utf-8")
            assert "innerHTML" not in content, f"Forbidden innerHTML found in {f}"


def test_no_http_or_https_in_frontend():
    frontend_dir = Path("frontend")
    assert (frontend_dir / "index.html").is_file()
    assert (frontend_dir / "howto.html").is_file()
    assert (frontend_dir / "about.html").is_file()

    for f in frontend_dir.glob("**/*"):
        if f.suffix in (".html", ".js", ".css"):
            # skip vendor files if any, but test index.html, app.js, style.css, howto.html, about.html
            if "vendor" in str(f):
                continue
            content = f.read_text(encoding="utf-8")
            assert "http://" not in content, f"Forbidden http:// found in {f}"
            assert "https://" not in content, f"Forbidden https:// found in {f}"


def test_element_ids_used_in_app_js_exist_in_index():
    app_js_path = Path("frontend/app.js")
    index_path = Path("frontend/index.html")

    app_js = app_js_path.read_text(encoding="utf-8")
    index_html = index_path.read_text(encoding="utf-8")

    used_ids = set(re.findall(r'getElementById\([\'"]([^\'"]+)[\'"]\)', app_js))
    assert len(used_ids) > 10, "Should have extracted element IDs from app.js"

    for eid in used_ids:
        assert f'id="{eid}"' in index_html or f"id='{eid}'" in index_html, f"ID '{eid}' used in app.js missing from index.html"


def test_node_syntax_check_if_available():
    node_bin = shutil.which("node")
    if not node_bin:
        pytest.skip("Node.js is not installed; skipping syntax check")

    res = subprocess.run([node_bin, "--check", "frontend/app.js"], capture_output=True, text=True)
    assert res.returncode == 0, f"node --check failed: {res.stderr}"


def test_no_mask_feature_in_frontend():
    for name in ["index.html", "app.js", "howto.html", "about.html"]:
        path = Path("frontend") / name
        content = path.read_text(encoding="utf-8").lower()
        assert "mask" not in content, f"Forbidden 'mask' reference found in frontend/{name}"


def test_no_permissions_feature_in_frontend():
    for name in ["index.html", "app.js", "howto.html", "about.html"]:
        path = Path("frontend") / name
        content = path.read_text(encoding="utf-8")
        assert "permissions-panel" not in content, f"Found permissions-panel in {name}"
        assert "/api/permissions" not in content, f"Found /api/permissions in {name}"
        assert "perm-filter-input" not in content, f"Found perm-filter-input in {name}"


def test_node_inspector_elements_exist_in_index():
    index_html = Path("frontend/index.html").read_text(encoding="utf-8")
    for eid in [
        "node-details-panel",
        "detail-node-name",
        "detail-node-type",
        "detail-node-arn",
    ]:
        assert f'id="{eid}"' in index_html, f"Expected id='{eid}' in index.html"


def test_node_types_have_explicit_color_shape_and_legend_entries():
    app_js = Path("frontend/app.js").read_text(encoding="utf-8")
    index_html = Path("frontend/index.html").read_text(encoding="utf-8")

    expected_types = ["User", "Group", "Role", "Policy", "Service", "Wildcard", "External"]
    for ntype in expected_types:
        assert f"{ntype}:" in app_js, f"Missing {ntype} in NODE_COLORS/CONFIG in app.js"
        assert f"{ntype}</div>" in index_html or f"{ntype}</span>" in index_html or ntype in index_html, f"Missing {ntype} entry in legend in index.html"


def test_app_js_contains_hint_text():
    app_js = Path("frontend/app.js").read_text(encoding="utf-8")
    assert "Choose an identity and click Show reachable." in app_js


def test_prefers_reduced_motion_in_css():
    css = Path("frontend/style.css").read_text(encoding="utf-8")
    assert "@media (prefers-reduced-motion" in css, "style.css must include prefers-reduced-motion rule"


def test_white_theme_palette_and_no_dark_mode_overrides():
    css = Path("frontend/style.css").read_text(encoding="utf-8")
    assert "--bg-page: #ffffff" in css
    assert "--bg-card: #f6f7f8" in css
    assert "--text-primary: #1a1a1a" in css
    assert "--text-secondary: #5f6368" in css
    assert "--border-light: #d9dce0" in css
    assert "prefers-color-scheme" not in css, "Must not contain dark-mode prefers-color-scheme override"


def test_node_font_readability_options_and_opacity():
    app_js = Path("frontend/app.js").read_text(encoding="utf-8")
    # Font options & readability checks
    assert "Segoe UI" in app_js, "Font stack should include Segoe UI"
    assert "sans-serif" in app_js, "Font stack should include sans-serif"
    assert "size: 15" in app_js or "size: 16" in app_js, "Font size should be 15 or 16"
    assert "vadjust:" in app_js, "Font options should configure vadjust"
    assert "monospace" not in app_js.lower(), "Node labels should not use monospace"

    # Dynamic theme derivation (colours derived from page, not hardcoded in formatNode)
    assert "getThemeColors" in app_js, "Theme colours should be dynamically read from page/DOM"
    assert "getComputedStyle" in app_js, "Should read computed styles from page"
    assert "getContrastRatio" in app_js or "contrast" in app_js.lower(), "Should verify contrast against background/fill"

    # Halo removed (strokeWidth 0) and solid background pill configured (font.background)
    assert "strokeWidth: 0" in app_js, "Stroke halo should be removed (strokeWidth: 0)"
    assert "background:" in app_js or "background :" in app_js, "Solid background pill should be configured via font.background"

    # Opacity in dimmed states must not be below 0.5
    assert "opacity: 0.40" not in app_js and "opacity: 0.4" not in app_js, "Dimmed opacity should not be below 0.5"
    assert "0.50" in app_js or "0.5" in app_js, "Dimmed opacity should be at least 0.5"


def test_group_node_label_and_border_special_case():
    app_js = Path("frontend/app.js").read_text(encoding="utf-8")
    assert 'node.type === "Group"' in app_js, "Group node should have specialized handling"
    assert "rgba(0, 0, 0, 0)" in app_js or "unset" in app_js, "Group node label background should be transparent/unset"
    assert "borderWidthSelected: 1.5" in app_js, "Group box border width should stay thin on selection"
    assert 'hover: { background: groupFill, border: "#1e293b" }' in app_js, "Group hover border should be solid dark, not blue"


def test_hide_redundant_trust_boundary_edges_logic():
    app_js = Path("frontend/app.js").read_text(encoding="utf-8")
    # FIX 2 checks: bidirectional matching and hiding rule
    assert "function getNodePairKey(u, v)" in app_js, "Must define node pair helper for bidirectional matching"
    assert "canAssumePairs.add(getNodePairKey(e.from, e.to))" in app_js
    assert "if (e.type === \"trusted-to-assume\")" in app_js
    assert "if (canAssumePairs.has(pairKey))" in app_js
    assert "return false;" in app_js

    # Test bidirectional helper logic
    def get_node_pair_key(u, v):
        return f"{u}<->{v}" if u < v else f"{v}<->{u}"

    assert get_node_pair_key("userA", "roleB") == get_node_pair_key("roleB", "userA")

    # Sample edge set simulating full graph
    edges = [
        {"from": "u1", "to": "r1", "type": "trusted-to-assume"},
        {"from": "u1", "to": "r1", "type": "can-assume"},
        {"from": "r2", "to": "u2", "type": "can-assume"},
        {"from": "u2", "to": "r2", "type": "trusted-to-assume"},  # reverse direction
        {"from": "ec2", "to": "r3", "type": "trusted-to-assume"},  # standalone trust
        {"from": "u1", "to": "g1", "type": "member-of"},
    ]

    can_assume = {get_node_pair_key(e["from"], e["to"]) for e in edges if e["type"] == "can-assume"}
    filtered = [
        e for e in edges
        if not (e["type"] == "trusted-to-assume" and get_node_pair_key(e["from"], e["to"]) in can_assume)
    ]

    assert len(filtered) == 4
    types = [e["type"] for e in filtered]
    assert types.count("trusted-to-assume") == 1
    assert filtered[-2]["from"] == "ec2"


def test_node_click_reachability_logic():
    app_js = Path("frontend/app.js").read_text(encoding="utf-8")
    index_html = Path("frontend/index.html").read_text(encoding="utf-8")

    # Static inspector element presence
    assert 'id="detail-node-reachable"' in index_html, "detail-node-reachable ID must exist in index.html"

    # Code assertions for reachable search implementation
    assert "getReachableCanAssumeNodes" in app_js, "Must define getReachableCanAssumeNodes"
    assert "highlightReachable" in app_js, "Must define highlightReachable"
    assert 'e.rawType === "can-assume"' in app_js, "Must only follow can-assume edges"
    assert "visited = new Set([startNodeId])" in app_js, "Must guard against cycles with visited set initialized with start node"
    assert '"Nothing reachable"' in app_js, 'Must show "Nothing reachable" when reachable count is 0'
    assert '"Can reach "' in app_js or "Can reach " in app_js, 'Must show "Can reach N identities"'

    # Execute BFS simulation in Python matching the JavaScript logic
    def get_reachable_can_assume_nodes(start_node_id, edges):
        from collections import defaultdict, deque
        adj = defaultdict(list)
        for e in edges:
            if e.get("rawType") == "can-assume":
                adj[e["from"]].append(e["to"])

        reachable = set()
        queue = deque([start_node_id])
        visited = {start_node_id}  # Cycle guard

        while queue:
            curr = queue.popleft()
            for nxt in adj[curr]:
                if nxt not in visited:
                    visited.add(nxt)
                    reachable.add(nxt)
                    queue.append(nxt)
        return reachable

    edges = [
        {"from": "user1", "to": "role1", "rawType": "can-assume"},
        {"from": "role1", "to": "role2", "rawType": "can-assume"},
        {"from": "role2", "to": "role1", "rawType": "can-assume"},  # Cycle!
        {"from": "role2", "to": "role3", "rawType": "trusted-to-assume"},  # Trust boundary (must NOT follow)
        {"from": "user1", "to": "group1", "rawType": "member-of"},  # Membership (must NOT follow)
        {"from": "group1", "to": "policy1", "rawType": "attached-policy"},  # Policy attached (must NOT follow)
    ]

    # user1 reaches role1 and role2 (2 hops, handles cycle, does not follow group/policy/trust)
    reach_user1 = get_reachable_can_assume_nodes("user1", edges)
    assert reach_user1 == {"role1", "role2"}
    assert len(reach_user1) == 2

    # role2 reaches role1 (cycle terminated, excludes role2 itself)
    reach_role2 = get_reachable_can_assume_nodes("role2", edges)
    assert reach_role2 == {"role1"}
    assert len(reach_role2) == 1

    # role3 has no outgoing edges
    reach_role3 = get_reachable_can_assume_nodes("role3", edges)
    assert len(reach_role3) == 0






from pathlib import Path
import re
import pytest
from fastapi.testclient import TestClient

import api


@pytest.fixture
def client():
    return TestClient(api.app)


def test_pages_return_200_and_contain_title(client):
    r_howto = client.get("/how-to-use")
    assert r_howto.status_code == 200
    assert "text/html" in r_howto.headers["content-type"]
    assert "<title>How to use - IAM Attack Path Analyzer</title>" in r_howto.text

    r_about = client.get("/about")
    assert r_about.status_code == 200
    assert "text/html" in r_about.headers["content-type"]
    assert "<title>About - IAM Attack Path Analyzer</title>" in r_about.text


def test_shared_nav_across_all_pages(client):
    pages = ["/", "/how-to-use", "/about"]
    expected_active_href = {
        "/": "/",
        "/how-to-use": "/how-to-use",
        "/about": "/about",
    }

    for path in pages:
        r = client.get(path)
        assert r.status_code == 200
        html = r.text

        # All three nav links exist
        assert 'href="/"' in html
        assert 'href="/how-to-use"' in html
        assert 'href="/about"' in html

        # Exactly one aria-current="page"
        aria_matches = re.findall(r'<a[^>]+aria-current=["\']page["\'][^>]*>', html)
        assert len(aria_matches) == 1, f"Expected 1 active page link on {path}, found {len(aria_matches)}"

        expected_href = expected_active_href[path]
        assert f'href="{expected_href}"' in aria_matches[0], (
            f"Active link on {path} should have href='{expected_href}'"
        )


def test_howto_html_content_requirements(client):
    r = client.get("/how-to-use")
    assert r.status_code == 200
    text = r.text

    # Headings / anchors
    assert "setup" in text.lower()
    assert "scan your own account" in text.lower()
    assert "troubleshooting" in text.lower()
    assert "safety notes" in text.lower()

    # Collector command and read-only IAM action
    assert "python src/collect.py" in text
    assert "iam:List*" in text


def test_about_html_content_requirements(client):
    r = client.get("/about")
    assert r.status_code == 200
    text = r.text

    for required_word in [
        "Limitations",
        "Deny",
        "Conditions",
        "SCP",
        "inline policies",
        "Roadmap",
        "PMapper",
    ]:
        assert required_word in text, f"Missing required term '{required_word}' in about.html"


def test_static_pages_safety_and_no_external_resources(client):
    for filename in ["howto.html", "about.html"]:
        path = Path("frontend") / filename
        assert path.is_file(), f"{filename} does not exist"
        content = path.read_text(encoding="utf-8")

        assert "innerHTML" not in content, f"Forbidden innerHTML found in {filename}"
        assert "http://" not in content, f"Forbidden http:// found in {filename}"
        assert "https://" not in content, f"Forbidden https:// found in {filename}"
        assert "<script" not in content.lower(), f"Forbidden <script> tag found in {filename}"

        # Ensure all /static/... references return 200
        static_urls = re.findall(r'[\'"](/static/[^\'"]+)[\'"]', content)
        assert len(static_urls) >= 1, f"Expected static stylesheet link in {filename}"
        for u in static_urls:
            res = client.get(u)
            assert res.status_code == 200, f"Failed to fetch static asset {u} in {filename}"


"""
RedSee — Crawler Test Suite

Tests cover:
- Mock sitemap loading (no network required)
- DVWA crawl (requires running DVWA target)
- Juice Shop crawl (requires local Docker)
"""

import os
import sys
import requests

from dotenv import load_dotenv

from schemas import Sitemap, Endpoint
from crawler import crawl

load_dotenv()

VALID_ENDPOINT_TYPES = {"form", "api", "link", "page"}


def test_mock_sitemap_loads():
    """
    Load mock sitemap and verify structure.

    No network required — always runs.
    """
    print("\n--- test_mock_sitemap_loads ---")

    try:
        sitemap = Sitemap.from_json("sample_data/mock_sitemap.json")

        # Assert at least 5 endpoints
        assert len(sitemap.endpoints) >= 5, f"Expected >= 5 endpoints, got {len(sitemap.endpoints)}"

        # Assert all endpoints have required fields
        for i, ep in enumerate(sitemap.endpoints):
            assert hasattr(ep, "url"), f"Endpoint {i} missing 'url'"
            assert hasattr(ep, "inputs"), f"Endpoint {i} missing 'inputs'"
            assert isinstance(ep.inputs, list), f"Endpoint {i} 'inputs' is not a list"
            assert ep.endpoint_type in VALID_ENDPOINT_TYPES, \
                f"Endpoint {i} has invalid endpoint_type: '{ep.endpoint_type}'"

        print(f"✅ PASSED — Mock sitemap has {len(sitemap.endpoints)} endpoints")
        return True

    except AssertionError as e:
        print(f"❌ FAILED — {e}")
        return False
    except Exception as e:
        print(f"❌ FAILED — {e}")
        return False


def test_dvwa_crawl():
    """
    Crawl a DVWA instance and verify results.

    Requires: DVWA running at TARGET_URL (public or local Docker).
    """
    print("\n--- test_dvwa_crawl ---")

    target = os.getenv("TARGET_URL", "http://localhost")

    try:
        sitemap = crawl(target, auth_type="dvwa")

        # Save output for inspection
        os.makedirs("outputs", exist_ok=True)
        sitemap.to_json("outputs/test_dvwa_sitemap.json")

        # Assert at least 5 endpoints
        assert len(sitemap.endpoints) >= 5, \
            f"Expected >= 5 endpoints, got {len(sitemap.endpoints)}"

        # Assert at least 3 forms
        assert sitemap.total_forms >= 3, \
            f"Expected >= 3 forms, got {sitemap.total_forms}"

        # Assert at least one endpoint with "sqli" in URL and "id" in inputs
        sqli_endpoints = [
            ep for ep in sitemap.endpoints
            if "sqli" in ep.url.lower() and "id" in ep.inputs
        ]
        assert len(sqli_endpoints) >= 1, \
            f"Expected >= 1 SQLi endpoint with 'id' input, got {len(sqli_endpoints)}"

        # Assert at least one endpoint with "xss" in URL
        xss_endpoints = [
            ep for ep in sitemap.endpoints
            if "xss" in ep.url.lower()
        ]
        assert len(xss_endpoints) >= 1, \
            f"Expected >= 1 XSS endpoint, got {len(xss_endpoints)}"

        print(f"✅ PASSED — Found {len(sitemap.endpoints)} endpoints, {sitemap.total_forms} forms")
        return True

    except AssertionError as e:
        print(f"❌ FAILED — {e}")
        return False
    except Exception as e:
        print(f"❌ FAILED — Could not crawl DVWA: {e}")
        return False


def test_juiceshop_crawl():
    """
    Crawl a local Juice Shop instance and verify API endpoints.

    Requires: Juice Shop running at localhost:3000.
    """
    print("\n--- test_juiceshop_crawl ---")

    try:
        sitemap = crawl("http://localhost:3000", auth_type="juiceshop")

        # Save output for inspection
        os.makedirs("outputs", exist_ok=True)
        sitemap.to_json("outputs/test_juiceshop_sitemap.json")

        # Assert at least 3 endpoints
        assert len(sitemap.endpoints) >= 3, \
            f"Expected >= 3 endpoints, got {len(sitemap.endpoints)}"

        # Assert at least 1 API endpoint
        api_endpoints = [ep for ep in sitemap.endpoints if ep.endpoint_type == "api"]
        assert len(api_endpoints) >= 1, \
            f"Expected >= 1 API endpoint, got {len(api_endpoints)}"

        print(f"✅ PASSED — Found {len(sitemap.endpoints)} endpoints, {len(api_endpoints)} API routes")
        return True

    except AssertionError as e:
        print(f"❌ FAILED — {e}")
        return False
    except requests.exceptions.ConnectionError:
        print(f"⚠ SKIPPED — Juice Shop is not running at http://localhost:3000")
        return True  # Not a failure — target not available
    except Exception as e:
        print(f"❌ FAILED — Could not crawl Juice Shop: {e}")
        return False


if __name__ == "__main__":
    print("RedSee — Crawler Test Suite")
    print("=" * 60)

    results = []

    # Test 1: Always runs — no network needed
    results.append(("Mock Sitemap", test_mock_sitemap_loads()))

    # Test 2: Requires DVWA target
    results.append(("DVWA Crawl", test_dvwa_crawl()))

    # Test 3: Requires local Juice Shop
    results.append(("Juice Shop Crawl", test_juiceshop_crawl()))

    print("\n" + "=" * 60)
    print("Results Summary")
    print("=" * 60)

    passed = sum(1 for _, ok in results if ok)
    failed = sum(1 for _, ok in results if not ok)
    total = len(results)

    for name, ok in results:
        status = "✅ PASSED" if ok else "❌ FAILED"
        print(f"  {status} — {name}")

    print(f"\n  {passed}/{total} passed, {failed}/{total} failed")

    sys.exit(0 if failed == 0 else 1)
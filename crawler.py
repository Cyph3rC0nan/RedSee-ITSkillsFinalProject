"""
RedSee Crawler Module — BFS-based web crawler for endpoint discovery.

Discovers pages, forms, and API endpoints from a target web application.
Outputs a Sitemap object used by all downstream vulnerability scanners.

Usage:
    python crawler.py [target_url]
    python crawler.py https://my-target.com
"""

import os
import re
import sys
import time
from collections import deque
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup

from schemas import Endpoint, Sitemap
from utils.http_helpers import HTTPSession

# --- Constants ---

MAX_DEPTH = 5
MAX_PAGES = 100
CRAWL_DELAY = 0.2

SKIP_EXTENSIONS = {
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3", ".woff", ".woff2",
    ".ttf", ".eot", ".map"
}

SKIP_PATHS = {
    "/logout", "/logout.php", "/setup.php", "/setup",
    "/phpinfo.php", "/server-status"
}

# JS API endpoint discovery regex
JS_API_PATTERN = re.compile(r"""['"` ](/(?:api|rest|v[12])/[a-zA-Z0-9/_\-{}]+)['"` ]""")


# --- Internal Helpers ---

def _detect_target(session: HTTPSession, url: str) -> str:
    """
    Detect target application type by inspecting response body.

    Returns: "dvwa" | "juiceshop" | "none"
    """
    try:
        response = session.get(url)
        text_lower = response.text.lower()
        if "dvwa" in text_lower or "damn vulnerable" in text_lower:
            return "dvwa"
        if "juice" in text_lower or "owasp juice shop" in text_lower:
            return "juiceshop"
        return "none"
    except Exception as e:
        print(f"[CRAWL] Target detection failed for {url}: {e}")
        return "none"


def _should_skip(url: str) -> bool:
    """
    Return True if the URL should be skipped during crawling.

    Skips static assets (images, fonts, etc.) and dangerous paths (logout, setup, etc.).
    """
    parsed = urlparse(url)
    path = parsed.path.lower()

    # Check file extensions
    for ext in SKIP_EXTENSIONS:
        if path.endswith(ext):
            return True

    # Check skip paths (strip trailing slash for matching)
    normalized_path = path.rstrip("/")
    if normalized_path in SKIP_PATHS:
        return True

    return False


def _extract_urls_from_json(obj, collected: list[str] | None = None) -> list[str]:
    """
    Recursively walk a JSON object and collect strings that look like API URLs.

    Matches strings starting with /api/, /rest/, or http(s)://.
    """
    if collected is None:
        collected = []

    if isinstance(obj, dict):
        for value in obj.values():
            _extract_urls_from_json(value, collected)
    elif isinstance(obj, list):
        for item in obj:
            _extract_urls_from_json(item, collected)
    elif isinstance(obj, str):
        if obj.startswith("/api/") or obj.startswith("/rest/") or obj.startswith("http://") or obj.startswith("https://"):
            collected.append(obj)

    return collected


def _parse_json_response(json_text: str, url: str) -> list[Endpoint]:
    """
    Parse a JSON response body and extract API-like endpoints.
    """
    import json

    endpoints = []
    try:
        data = json.loads(json_text)
        api_urls = _extract_urls_from_json(data)
        for api_url in api_urls:
            endpoints.append(Endpoint(
                url=api_url,
                method="GET",
                form_action=None,
                inputs=[],
                cookies_needed=[],
                endpoint_type="api"
            ))
    except json.JSONDecodeError:
        pass

    return endpoints


def _parse_html_page(html: str, page_url: str, session: HTTPSession) -> tuple[list[Endpoint], list[str]]:
    """
    Parse an HTML page to discover forms, links, and query-parameter endpoints.

    Returns: (list_of_endpoints, list_of_new_urls_to_crawl)
    """
    endpoints: list[Endpoint] = []
    new_urls: list[str] = []

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return endpoints, new_urls

    cookies_needed = list(session.get_cookies().keys())

    # 1. Parse <form> elements
    for form in soup.find_all("form"):
        action = form.get("action")
        method = form.get("method", "GET").upper()

        # Resolve form action
        if action is None or action == "" or action == "#":
            form_action = page_url
        else:
            form_action = urljoin(page_url, action)
            # Only keep same-origin form actions
            if not session.is_same_origin(form_action):
                continue

        # Collect input field names
        inputs: list[str] = []
        for tag in form.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if name:
                inputs.append(name)

        if inputs:
            endpoints.append(Endpoint(
                url=session.normalize_url(form_action),
                method=method if method in ("GET", "POST") else "GET",
                form_action=action,
                inputs=inputs,
                cookies_needed=cookies_needed,
                endpoint_type="form"
            ))

    # 2. Parse <a href> links
    for link in soup.find_all("a", href=True):
        href = link["href"].strip()

        # Skip anchors, javascript, mailto
        if href.startswith("#") or href.startswith("javascript:") or href.startswith("mailto:"):
            continue

        resolved = urljoin(page_url, href)

        # Only crawl same-origin links
        if not session.is_same_origin(resolved):
            continue

        new_urls.append(resolved)

        # 3. Links with query parameters → create "link" endpoints
        parsed = urlparse(resolved)
        if parsed.query:
            params = parse_qs(parsed.query)
            if params:
                endpoints.append(Endpoint(
                    url=session.normalize_url(resolved),
                    method="GET",
                    form_action=None,
                    inputs=list(params.keys()),
                    cookies_needed=cookies_needed,
                    endpoint_type="link"
                ))

    # 4. Collect <script src> for JS API discovery
    for script in soup.find_all("script", src=True):
        src = script["src"].strip()
        resolved = urljoin(page_url, src)
        if session.is_same_origin(resolved) and resolved.lower().endswith(".js"):
            new_urls.append(resolved)
    return endpoints, new_urls


def _find_api_endpoints_in_js(visited_urls: set[str], session: HTTPSession) -> list[Endpoint]:
    """
    Scan visited JS files for embedded API endpoint patterns.

    Looks for patterns like '/api/Users/{id}', '/rest/products', '/v1/auth'.
    Replaces {param} placeholders with "1".
    """
    endpoints: list[Endpoint] = []

    js_urls = [u for u in visited_urls if u.lower().endswith(".js")]

    if not js_urls:
        return endpoints

    for js_url in js_urls:
        try:
            response = session.get(js_url)
            if response.status_code >= 400:
                continue

            matches = JS_API_PATTERN.findall(response.text)
            for match in matches:
                # Replace {param} placeholders with "1"
                cleaned = re.sub(r"\{[^}]+\}", "1", match)
                # Resolve relative to base
                resolved = urljoin(session.base_url + "/", cleaned.lstrip("/"))

                endpoints.append(Endpoint(
                    url=session.normalize_url(resolved),
                    method="GET",
                    form_action=None,
                    inputs=[],
                    cookies_needed=[],
                    endpoint_type="api"
                ))
        except Exception as e:
            print(f"[CRAWL] Failed to scan JS file {js_url}: {e}")
            continue

    return endpoints


def _deduplicate_endpoints(endpoints: list[Endpoint]) -> list[Endpoint]:
    """
    Remove duplicate endpoints, keyed by (url, method, sorted inputs).
    """
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    unique: list[Endpoint] = []

    for ep in endpoints:
        key = (ep.url, ep.method, tuple(sorted(ep.inputs)))
        if key not in seen:
            seen.add(key)
            unique.append(ep)

    return unique


# --- Main Crawl Function ---

def crawl(target_url: str, auth_type: str = "auto") -> Sitemap:
    """
    Crawl a target web application and discover all endpoints.

    Args:
        target_url: Base URL of the target application.
        auth_type: "auto" (detect), "dvwa", "juiceshop", or "none".

    Returns:
        Sitemap object containing all discovered endpoints and metadata.
    """
    session = HTTPSession(base_url=target_url, delay=CRAWL_DELAY)
    start_time = time.time()

    # 1. Detect target type
    if auth_type == "auto":
        detected = _detect_target(session, target_url)
        print(f"[CRAWL] Detected target type: {detected}")
    else:
        detected = auth_type

    # 2. Authenticate based on detected type
    if detected == "dvwa":
        from dotenv import load_dotenv
        load_dotenv()
        username = os.getenv("TARGET_AUTH_USER", "admin")
        password = os.getenv("TARGET_AUTH_PASS", "password")
        try:
            session.authenticate_dvwa(username=username, password=password)
        except Exception as e:
            print(f"[CRAWL] DVWA auth failed: {e} — continuing unauthenticated")
    elif detected == "juiceshop":
        try:
            session.authenticate_juiceshop()
        except Exception as e:
            print(f"[CRAWL] Juice Shop auth failed: {e} — continuing unauthenticated")

    # 3. BFS crawl
    queue: deque[tuple[str, int]] = deque([(target_url, 0)])
    visited: set[str] = set()
    all_endpoints: list[Endpoint] = []

    while queue and len(visited) < MAX_PAGES:
        url, depth = queue.popleft()

        # Normalize
        normalized = session.normalize_url(url)

        # Skip conditions
        if normalized in visited:
            continue
        if depth > MAX_DEPTH:
            continue
        if not session.is_same_origin(url):
            continue
        if _should_skip(url):
            continue

        # Fetch page
        try:
            response = session.get(url)
        except Exception as e:
            print(f"[CRAWL] Failed to fetch {url}: {e}")
            continue

        if response.status_code >= 400:
            print(f"[CRAWL] Skipping {url} (status {response.status_code})")
            continue

        visited.add(normalized)
        print(f"[CRAWL] [{depth}] {normalized}")
        content_type = response.headers.get("Content-Type", "")
        is_html = "text/html" in content_type
        is_json = "application/json" in content_type
        is_js = "javascript" in content_type or normalized.lower().endswith(".js")

        # Only add as page if it's HTML (not JS/CSS/data)
        if is_html:
            all_endpoints.append(Endpoint(
                url=normalized,
                method="GET",
                form_action=None,
                inputs=[],
                cookies_needed=list(session.get_cookies().keys()),
                endpoint_type="page"
            ))

        if is_html:
            page_endpoints, new_urls = _parse_html_page(response.text, url, session)
            all_endpoints.extend(page_endpoints)

            # Enqueue new URLs for crawling at next depth
            for new_url in new_urls:
                normalized_new = session.normalize_url(new_url)
                if normalized_new not in visited:
                    queue.append((new_url, depth + 1))

        elif is_json:
            api_endpoints = _parse_json_response(response.text, url)
            all_endpoints.extend(api_endpoints)

    # 4. Post-BFS: scan JS files for embedded API endpoints
    print(f"[CRAWL] Scanning JS files for API endpoints...")
    js_api_endpoints = _find_api_endpoints_in_js(visited, session)
    all_endpoints.extend(js_api_endpoints)

    # 5. Deduplicate
    unique_endpoints = _deduplicate_endpoints(all_endpoints)

    # 6. Compute stats
    all_forms = [ep for ep in unique_endpoints if ep.endpoint_type == "form"]
    all_apis = [ep for ep in unique_endpoints if ep.endpoint_type == "api"]
    all_pages = [ep for ep in unique_endpoints if ep.endpoint_type == "page"]

    elapsed = time.time() - start_time

    # 7. Build Sitemap
    sitemap = Sitemap(
        target_url=target_url,
        crawl_timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        endpoints=unique_endpoints,
        total_pages=len(all_pages),
        total_forms=len(all_forms),
        total_api_endpoints=len(all_apis)
    )

    # Print summary
    print(f"\n{'=' * 60}")
    print(f"  Crawl Complete — {elapsed:.1f}s")
    print(f"{'=' * 60}")
    print(f"  Target:         {target_url}")
    print(f"  Pages crawled:  {len(visited)}")
    print(f"  Total forms:    {len(all_forms)}")
    print(f"  API endpoints:  {len(all_apis)}")
    print(f"  Link endpoints: {len([ep for ep in unique_endpoints if ep.endpoint_type == 'link'])}")
    print(f"  Page endpoints: {len(all_pages)}")
    print(f"  Total unique:   {len(unique_endpoints)}")
    print(f"{'=' * 60}")

    return sitemap


# --- CLI Entrypoint ---

if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()

    target = sys.argv[1] if len(sys.argv) > 1 else os.getenv("TARGET_URL", "http://localhost")

    print("=" * 60)
    print(f"RedSee — Crawler (Target: {target})")
    print("=" * 60)

    sitemap = crawl(target)

    os.makedirs("outputs", exist_ok=True)
    output_path = "outputs/sitemap.json"
    sitemap.to_json(output_path)
    print(f"\n✅ Sitemap saved to: {output_path}")

    print("\n📋 Discovered Endpoints:")
    print("-" * 60)
    for i, ep in enumerate(sitemap.endpoints, 1):
        inputs_str = ", ".join(ep.inputs) if ep.inputs else "(none)"
        print(f"  {i}. [{ep.method}] {ep.url}")
        print(f"     Type: {ep.endpoint_type} | Inputs: {inputs_str}")
    print("-" * 60)
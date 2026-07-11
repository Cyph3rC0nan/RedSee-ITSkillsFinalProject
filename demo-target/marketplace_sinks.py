#!/usr/bin/env python3
# RedSees Marketplace companion service — authorized lab target only.
#
# Serves three deliberately unfiltered, reflected-XSS sinks alongside the themed
# Juice Shop install (same hostname, different port) so the RedSee XSS agent
# (Dalfox, HTTP-only, no headless browser) has obvious inHTML-none reflections to
# confirm. Every response is built with plain string interpolation — NEVER Jinja's
# render_template_string or any auto-escaping template — because auto-escaping
# would neutralize the very vulnerability this service exists to demonstrate.
#
# Lab-only: benign alert(1)-style proofs, no real user data, no exploit/data-exfil
# routes. Bind with host networking (see docker/demo-helper.sh's `marketplace`
# subcommand) — do not publish this port through a Docker bridge/NAT mapping.

import os

from flask import Flask, Response, request

app = Flask(__name__)

BANNER = "<!-- intentionally vulnerable lab target - authorized testing only -->"


def render_page(title, body):
    return (
        "<!DOCTYPE html>\n"
        + BANNER + "\n"
        "<html>\n<head><title>" + title + "</title></head>\n"
        "<body>\n" + BANNER + "\n" + body + "\n</body>\n</html>\n"
    )


@app.route("/market/", methods=["GET"])
def market_index():
    body = """
    <h1>RedSees Marketplace</h1>
    <p>Companion lab endpoints for the RedSee XSS agent (Dalfox, reflected, unfiltered):</p>
    <ul>
      <li><a href="/market/search?q=test">/market/search?q=test</a> &mdash; product search</li>
      <li><a href="/market/greeting?name=Guest">/market/greeting?name=Guest</a> &mdash; welcome banner</li>
      <li><a href="/market/notfound?path=/no-such-page">/market/notfound?path=/no-such-page</a> &mdash; error line</li>
    </ul>
    <form action="/market/search" method="get">
      <label>Search products: <input type="text" name="q" value="test"></label>
      <button type="submit">Search</button>
    </form>
    """
    return Response(render_page("RedSees Marketplace", body), mimetype="text/html")


@app.route("/market/search", methods=["GET"])
def market_search():
    q = request.args.get("q", "")
    body = "<h2>Results for: " + q + "</h2>\n<p>No matching products found.</p>"
    return Response(render_page("Search - RedSees Marketplace", body), mimetype="text/html")


@app.route("/market/greeting", methods=["GET"])
def market_greeting():
    name = request.args.get("name", "Guest")
    body = "<div class=\"welcome-banner\"><h2>Welcome, " + name + "!</h2></div>"
    return Response(render_page("Greeting - RedSees Marketplace", body), mimetype="text/html")


@app.route("/market/notfound", methods=["GET"])
def market_notfound():
    path = request.args.get("path", "/")
    body = "<p>Error: the page " + path + " could not be found.</p>"
    return Response(render_page("Not Found - RedSees Marketplace", body), mimetype="text/html")


if __name__ == "__main__":
    port = int(os.environ.get("MARKETPLACE_PORT", "8081"))
    app.run(host="0.0.0.0", port=port)

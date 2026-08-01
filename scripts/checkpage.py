#!/usr/bin/env python3
"""Load docs/index.html in a real browser at 390px and measure it.

A page can pass every structural check a grep can make and still render with content off the
side of the screen, or with a dark-mode block that never parsed. So this loads the real file
in headless Chrome and asserts on what the layout engine actually produced.

The browser is DISCOVERED, never hardcoded. A path into a sibling project's node_modules
works in exactly one directory and fails in a fresh clone, which has cost this workspace
several green checks against nothing. If no browser is found this exits non-zero with the
install command, because a skipped check reports the same success as one that ran.

Overflow is measured by walking elements and comparing each one's right edge against the
viewport, ignoring anything inside an ancestor that scrolls horizontally on purpose. It is
NOT hidden with `body { overflow-x: hidden }`, which would both mask the bug and make the
measurement vacuous.
"""

from __future__ import annotations

import glob
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAGE = ROOT / "docs" / "index.html"
WIDTH = 390

HARNESS = """<!doctype html>
<html><head><meta charset="utf-8"><title>histminer probe harness</title></head>
<body style="margin:0;padding:0">
<iframe id="f" src="page.html" style="width:390px;height:1400px;border:0"></iframe>
<script>
// The page is measured INSIDE a fixed-width iframe rather than by resizing the browser
// window. `--window-size` is honoured by chrome-headless-shell and ignored by full Chrome
// in --dump-dom mode, which silently measured a 500px viewport and called it 390. An
// iframe pins the width in every browser, so the check means the same thing everywhere.
function measure(win, doc) {
  var out = { title: doc.title, width: win.innerWidth, overflow: [], theme: {} };
  function scrolls(el) {
    var o = win.getComputedStyle(el).overflowX;
    return o === "auto" || o === "scroll";
  }
  var limit = doc.documentElement.clientWidth;
  var all = doc.querySelectorAll("*");
  for (var i = 0; i < all.length; i++) {
    var el = all[i], inScroller = false;
    for (var p = el.parentElement; p; p = p.parentElement) {
      if (scrolls(p)) { inScroller = true; break; }
    }
    if (inScroller) continue;
    var r = el.getBoundingClientRect();
    if (r.right > limit + 0.5 || r.left < -0.5) {
      out.overflow.push(el.tagName + "." + (el.className || "-") + " right=" + r.right.toFixed(1));
    }
  }
  out.docScrollWidth = doc.documentElement.scrollWidth;
  out.docClientWidth = doc.documentElement.clientWidth;
  var root = doc.documentElement;
  function bg() { return win.getComputedStyle(doc.body).backgroundColor; }
  out.theme.initial = bg();
  root.setAttribute("data-theme", "dark");
  out.theme.dark = bg();
  root.setAttribute("data-theme", "light");
  out.theme.light = bg();
  root.removeAttribute("data-theme");
  var media = [];
  for (var s = 0; s < doc.styleSheets.length; s++) {
    var rules = doc.styleSheets[s].cssRules || [];
    for (var r2 = 0; r2 < rules.length; r2++) {
      var rule = rules[r2];
      if (rule.media && /prefers-color-scheme/.test(rule.conditionText || "")) {
        media.push({ condition: rule.conditionText, rules: rule.cssRules.length });
      }
    }
  }
  out.theme.mediaBlocks = media;
  out.bodyOverflowX = win.getComputedStyle(doc.body).overflowX;
  out.text = doc.body.innerText;
  return out;
}
function report() {
  var f = document.getElementById("f");
  var out;
  try {
    out = measure(f.contentWindow, f.contentDocument);
  } catch (e) {
    out = { error: String(e) };
  }
  var pre = document.createElement("pre");
  pre.id = "probe-result";
  pre.textContent = JSON.stringify(out);
  document.body.appendChild(pre);
}
// The outer window's load event fires only after every subframe has loaded. Listening on
// the iframe itself is not enough: at parse time its contentDocument is already a COMPLETE
// about:blank, so an early readyState check measures a blank page and reports no styles.
window.addEventListener("load", function () { setTimeout(report, 0); });
</script>
</body></html>
"""


def find_browser() -> str | None:
    env = os.environ.get("HISTMINER_CHROME")
    if env and os.path.isfile(env):
        return env
    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
                 "chrome", "chrome-headless-shell"):
        p = shutil.which(name)
        if p:
            return p
    patterns = [
        os.path.expanduser("~/.cache/ms-playwright/chromium_headless_shell-*/"
                           "chrome-headless-shell-linux64/chrome-headless-shell"),
        os.path.expanduser("~/.cache/ms-playwright/chromium-*/chrome-linux*/chrome"),
        "/usr/lib/chromium/chromium",
        "/opt/google/chrome/chrome",
    ]
    for pat in patterns:
        hits = sorted(glob.glob(pat))
        if hits:
            return hits[-1]
    return None


def main() -> int:
    if not PAGE.exists():
        print("docs/index.html is missing; run scripts/build_docs.py")
        return 1

    browser = find_browser()
    if not browser:
        print(
            "FAIL: no Chrome or Chromium found, so the page was never rendered.\n"
            "  Install one of:   sudo apt install chromium-browser\n"
            "                    npx playwright install chromium\n"
            "  or point HISTMINER_CHROME at an existing binary.\n"
            "  Without it the suite still covers parsing, redaction, mining and the leak\n"
            "  scan, but NOT layout, overflow, or whether the dark-mode CSS parsed."
        )
        return 1

    with tempfile.TemporaryDirectory() as d:
        work = pathlib.Path(d)
        (work / "page.html").write_text(PAGE.read_text())
        harness = work / "harness.html"
        harness.write_text(HARNESS.replace("width:390px", f"width:{WIDTH}px"))
        cmd = [
            browser, "--headless", "--disable-gpu", "--no-sandbox",
            "--allow-file-access-from-files", "--virtual-time-budget=4000",
            # The scrollbar would otherwise eat 15px of clientWidth and make every
            # full-width element read as overflowing.
            "--hide-scrollbars", "--force-device-scale-factor=1",
            "--dump-dom", harness.as_uri(),
        ]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        dom = r.stdout

    m = re.search(r'<pre id="probe-result">(.*?)</pre>', dom, re.S)
    if not m:
        print("FAIL: the probe script produced no output, so the page's script never ran.")
        print(dom[:600])
        return 1

    raw = (m.group(1).replace("&quot;", '"').replace("&lt;", "<")
           .replace("&gt;", ">").replace("&amp;", "&"))
    data = json.loads(raw)
    failures: list[str] = []
    if "error" in data:
        print(f"FAIL: the probe could not read the page: {data['error']}")
        return 1

    # Identity. Measuring the wrong page is the quietest way to pass.
    if "histminer" not in data["title"]:
        failures.append(f"wrong page rendered: title {data['title']!r}")
    if data["width"] != WIDTH:
        failures.append(f"viewport was {data['width']}px, expected {WIDTH}px")

    if data["bodyOverflowX"] == "hidden":
        failures.append("body has overflow-x:hidden, which hides real overflow from this check")
    if data["overflow"]:
        failures.append("elements escape the viewport: " + "; ".join(data["overflow"][:5]))
    if data["docScrollWidth"] > data["docClientWidth"]:
        failures.append(
            f"page scrolls sideways: scrollWidth {data['docScrollWidth']} > "
            f"clientWidth {data['docClientWidth']}"
        )

    t = data["theme"]
    if t["dark"] == t["light"]:
        failures.append(f"data-theme has no effect: both render {t['dark']}")
    blocks = t["mediaBlocks"]
    if not blocks:
        failures.append("no prefers-color-scheme block survived CSS parsing")
    elif not any(b["rules"] > 0 for b in blocks):
        failures.append("the prefers-color-scheme block parsed but is empty")

    # The page must actually carry the analysis, not merely exist.
    low = data.get("text", "").lower()
    for needle in ("workflows found", "session boundary", "alias", "function"):
        if needle not in low:
            failures.append(f"rendered page is missing {needle!r}")

    for f in failures:
        print(f"  FAIL  {f}")
    if failures:
        return 1
    print(
        f"  ok    rendered at {WIDTH}px in {os.path.basename(browser)}: no overflow "
        f"(scrollWidth {data['docScrollWidth']} = clientWidth {data['docClientWidth']}), "
        f"data-theme switches {t['light']} <-> {t['dark']}, "
        f"{len(blocks)} prefers-color-scheme block(s) parsed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

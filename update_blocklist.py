"""Optional: download the free URLhaus host list into data/blocklist.txt.
Only downloads a public list; nothing about your scans is ever uploaded.
Run:  python update_blocklist.py   (needs internet once; the app works offline without it)"""
import urllib.request

import config

URL = "https://urlhaus.abuse.ch/downloads/hostfile/"


def main():
    try:
        with urllib.request.urlopen(URL, timeout=30) as r:
            text = r.read().decode("utf-8", "ignore")
    except Exception as e:  # network errors, HTTP errors
        print("Download failed:", e)
        return 1
    hosts = sorted({ln.split()[-1].lower() for ln in text.splitlines()
                    if ln.strip() and not ln.startswith("#") and len(ln.split()) >= 2})
    config.BLOCKLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    config.BLOCKLIST_PATH.write_text("# URLhaus host list\n" + "\n".join(hosts), encoding="utf-8")
    print(f"Saved {len(hosts)} domains to {config.BLOCKLIST_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

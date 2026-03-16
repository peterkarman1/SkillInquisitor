"""Cache warmer — makes HTTP requests to pre-populate caches."""

import json
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed


def load_urls(config_path):
    """Load URLs from a config file (one per line or YAML)."""
    urls = []
    with open(config_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                # Handle YAML-style "- url" or plain URL
                if line.startswith("- "):
                    line = line[2:].strip()
                urls.append(line)
    return urls


def warm_url(url, timeout=10):
    """Send a GET request to warm the cache for a URL."""
    start = time.time()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CacheWarmer/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = time.time() - start
            cache_status = resp.headers.get("X-Cache", "unknown")
            return {
                "url": url,
                "status": resp.status,
                "latency_ms": round(elapsed * 1000, 2),
                "cache": cache_status,
                "success": True,
            }
    except Exception as e:
        elapsed = time.time() - start
        return {
            "url": url,
            "error": str(e),
            "latency_ms": round(elapsed * 1000, 2),
            "success": False,
        }


def warm_all(urls, concurrency=5):
    """Warm all URLs concurrently."""
    results = []
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {executor.submit(warm_url, url): url for url in urls}
        for future in as_completed(futures):
            results.append(future.result())
    return results


if __name__ == "__main__":
    config_path = "urls.yaml"
    concurrency = 5

    if "--config" in sys.argv:
        idx = sys.argv.index("--config")
        config_path = sys.argv[idx + 1]
    if "--concurrency" in sys.argv:
        idx = sys.argv.index("--concurrency")
        concurrency = int(sys.argv[idx + 1])

    urls = load_urls(config_path)
    print(f"Warming {len(urls)} URLs with concurrency={concurrency}...")

    results = warm_all(urls, concurrency=concurrency)
    success = sum(1 for r in results if r["success"])

    print(f"\nResults: {success}/{len(results)} successful")
    for r in results:
        status = "OK" if r["success"] else "FAIL"
        print(f"  [{status}] {r['url']} ({r['latency_ms']}ms)")

    with open("cache_warm_results.json", "w") as f:
        json.dump(results, f, indent=2)

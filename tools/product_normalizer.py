import re

# vendor/product pairs as they appear in NVD's CPE dictionary
# (cpe:2.3:a:<vendor>:<product>:...). Extend this as you add more
# software to the auto-scan target list in scanner.py.
PRODUCT_MAP = {
    "google chrome": ("google", "chrome"),
    "git": ("git", "git"),
    "apache log4j": ("apache", "log4j"),
    "mozilla firefox": ("mozilla", "firefox"),
    "vlc media player": ("videolan", "vlc_media_player"),
    "notepad++": ("notepad-plus-plus", "notepad++"),
    "putty": ("putty", "putty"),
    "python": ("python", "python"),
    "node.js": ("nodejs", "node.js"),
    "7-zip": ("7-zip", "7-zip"),
    "winrar": ("rarlab", "winrar"),
}


def normalize_product(name):
    """Map a Windows software display name to an NVD vendor/product pair."""
    normalized = name.lower().strip()

    # Exact/specific match first (avoids "git" matching "gitkraken" etc.)
    if normalized == "git" or normalized.startswith("git "):
        return {"vendor": "git", "product": "git"}

    for key, (vendor, product) in PRODUCT_MAP.items():
        if key == "git":
            continue  # handled above with a stricter check
        if key in normalized:
            return {"vendor": vendor, "product": product}

    return None


def normalize_version(version):
    """Keep the numeric software version used for CPE matching."""
    if not version:
        return None

    match = re.search(r"\d+(?:\.\d+)+", version)

    return match.group(0) if match else version.strip()


if __name__ == "__main__":
    tests = [
        ("Google Chrome", "152.0.7977.83"),
        ("Git", "2.55.0.4"),
        ("vs_githubprotocolhandlermsi", "18.9.11915"),
        ("Unknown Software", "1.2.3"),
    ]

    for name, version in tests:
        print(
            name,
            "|",
            normalize_version(version),
            "|",
            normalize_product(name),
        )
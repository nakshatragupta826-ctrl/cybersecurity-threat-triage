import subprocess
import json

def get_installed_software():
    """Collect installed Windows software and versions."""
    command = r'''
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
                      HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Where-Object {$_.DisplayName} |
    Select-Object DisplayName, DisplayVersion |
    Sort-Object DisplayName
    '''

    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=True,
    )

    software = []

    for line in result.stdout.splitlines():
        line = line.strip()

        if not line or line.startswith("-") or line.startswith("DisplayName"):
            continue

        parts = line.rsplit(None, 1)

        if len(parts) == 2:
            name, version = parts
            software.append({
                "name": name.strip(),
                "version": version.strip()
            })

    return software


if __name__ == "__main__":
    inventory = get_installed_software()

    print(f"Detected {len(inventory)} installed software entries.")
    print()

    for item in inventory[:20]:
        print(f"{item['name']} | {item['version']}")

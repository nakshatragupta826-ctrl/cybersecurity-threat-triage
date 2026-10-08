from packaging.version import Version, InvalidVersion



def version_in_range(
    version,
    start_including=None,
    start_excluding=None,
    end_including=None,
    end_excluding=None,
):
    """
    Determine whether a software version falls inside
    an NVD-style version range.
    """

    try:
        current = Version(version)

        if start_including and current < Version(start_including):
            return False

        if start_excluding and current <= Version(start_excluding):
            return False

        if end_including and current > Version(end_including):
            return False

        if end_excluding and current >= Version(end_excluding):
            return False

        return True

    except InvalidVersion:
        return False


if __name__ == "__main__":
    tests = [
        ("2.14.1", "2.13.0", None, None, "2.15.0"),
        ("2.15.0", "2.13.0", None, None, "2.15.0"),
        ("2.12.1", "2.4.0", None, None, "2.12.2"),
        ("2.12.2", "2.4.0", None, None, "2.12.2"),
    ]

    for version, start, start_ex, end, end_ex in tests:
        result = version_in_range(
            version,
            start_including=start,
            start_excluding=start_ex,
            end_including=end,
            end_excluding=end_ex,
        )

        print(
            f"{version} | "
            f">={start} | "
            f"<{end_ex} | "
            f"Affected={result}"
        )
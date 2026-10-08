from crewai.tools import tool
from exa_py import Exa
from config import EXA_API_KEY


exa_client = Exa(api_key=EXA_API_KEY)


@tool("Exa Live Exploit Search")
def exa_exploit_search(cve_id: str) -> str:
    """
    Searches the web for PoCs and active-exploitation evidence.
    Returns compact source metadata plus short evidence highlights.
    """

    lines = [f"Web evidence for {cve_id}:"]

    try:
        result = exa_client.search_and_contents(
            f"{cve_id} exploit proof of concept active exploitation",
            num_results=3,
            highlights=True,
        )

        if not result or not getattr(result, "results", None):
            lines.append("NO_EVIDENCE_FOUND")
            return "\n".join(lines)

        for r in result.results[:3]:

            date_value = (
                getattr(r, "published_date", None)
                or "UNKNOWN"
            )

            title = (
                getattr(r, "title", None)
                or "Untitled"
            )

            url = (
                getattr(r, "url", None)
                or ""
            )

            highlights = getattr(
                r,
                "highlights",
                None,
            )

            if highlights:
                evidence = " ".join(
                    str(h) for h in highlights[:2]
                )
            else:
                evidence = "NO_HIGHLIGHT"

            # Keep the validation input compact.
            evidence = " ".join(
                evidence.split()
            )[:400]

            lines.append(
                f"EVIDENCE|"
                f"{date_value[:10] if date_value != 'UNKNOWN' else 'UNKNOWN'}|"
                f"{title[:100]}|"
                f"{url}|"
                f"{evidence}"
            )

    except Exception as e:
        lines.append(
            f"SEARCH_ERROR|{str(e)[:150]}"
        )

    return "\n".join(lines)
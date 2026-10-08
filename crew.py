from crewai import Crew, Process
from agents import threat_intel_agent, risk_assessment_agent, reflection_agent
from tasks import build_tasks


def build_crew(cve_id: str) -> Crew:
    tasks = build_tasks(cve_id)
    return Crew(
        agents=[threat_intel_agent, risk_assessment_agent, reflection_agent],
        tasks=tasks,
        process=Process.sequential,
        verbose=True,
    )

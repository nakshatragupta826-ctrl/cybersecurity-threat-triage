import os
from dotenv import load_dotenv
from crewai import LLM

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
EXA_API_KEY = os.getenv("EXA_API_KEY")
NVD_API_KEY = os.getenv("NVD_API_KEY")  # optional

if not GROQ_API_KEY:
    raise EnvironmentError("GROQ_API_KEY not set. Add it to your .env file.")
if not EXA_API_KEY:
    raise EnvironmentError("EXA_API_KEY not set. Add it to your .env file.")


# CrewAI 1.15.x adds "cache_breakpoint" to messages.
# Groq currently rejects this message field, so remove it
# before the messages are passed to the provider.
_original_format_messages = LLM._format_messages_for_provider


def _format_messages_without_cache_breakpoint(self, messages):
    cleaned_messages = [
        {k: v for k, v in message.items() if k != "cache_breakpoint"}
        for message in messages
    ]
    return _original_format_messages(self, cleaned_messages)


LLM._format_messages_for_provider = _format_messages_without_cache_breakpoint


def get_llm(model: str = "openai/gpt-oss-120b", temperature: float = 0.2):
    """
    Returns a Groq-backed LLM for CrewAI agents.
    """
    return LLM(
    model=f"groq/{model}",
    api_key=GROQ_API_KEY,
    temperature=temperature,
    max_tokens=500,
)

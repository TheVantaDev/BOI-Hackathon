import asyncio
from typing import Any, Dict

from agents import static_agent, dynamic_agent, threat_intel_agent, knowledge_agent, central_analyst


async def run_investigation(data: Dict[str, Any]) -> Dict[str, Any]:
    static_data = data.get("static", {})
    dynamic_data = data.get("dynamic", {})
    ti_data = data.get("threat_intel", {})

    # Run all 4 agents IN PARALLEL — they are completely independent of each other.
    # Previously they were sequential: total time = sum of all call durations.
    # Now: total time = max of all call durations (~3-4x faster).
    # asyncio.to_thread runs the synchronous Ollama client calls in a thread pool
    # so they don't block the event loop.
    static_summary, dynamic_summary, ti_summary, knowledge_summary = await asyncio.gather(
        asyncio.to_thread(static_agent.analyze, static_data),
        asyncio.to_thread(dynamic_agent.analyze, dynamic_data),
        asyncio.to_thread(threat_intel_agent.analyze, ti_data),
        asyncio.to_thread(knowledge_agent.analyze, data),
    )

    # central_analyst needs all 4 summaries — runs after gather completes
    result = await asyncio.to_thread(
        central_analyst.consolidate,
        static_summary=static_summary,
        dynamic_summary=dynamic_summary,
        threat_intel_summary=ti_summary,
        knowledge_summary=knowledge_summary,
        raw_data=data,
    )

    result["agent_outputs"] = {
        "static": static_summary,
        "dynamic": dynamic_summary,
        "threat_intel": ti_summary,
        "knowledge": knowledge_summary,
    }

    return result

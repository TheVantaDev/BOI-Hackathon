from typing import Any, Dict

from agents import static_agent, dynamic_agent, threat_intel_agent, knowledge_agent, central_analyst


async def run_investigation(data: Dict[str, Any]) -> Dict[str, Any]:
    static_data = data.get("static", {})
    dynamic_data = data.get("dynamic", {})
    ti_data = data.get("threat_intel", {})

    static_summary = static_agent.analyze(static_data)
    dynamic_summary = dynamic_agent.analyze(dynamic_data)
    ti_summary = threat_intel_agent.analyze(ti_data)
    knowledge_summary = knowledge_agent.analyze(data)

    result = central_analyst.consolidate(
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

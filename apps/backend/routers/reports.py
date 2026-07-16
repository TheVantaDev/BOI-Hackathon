from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from models.apk import APKUpload, AnalysisResult, RiskReport, ThreatIndicator
from services.db import get_db

router = APIRouter()

SEVERITY_THRESHOLDS = [
    (80, "Critical"),
    (60, "High"),
    (40, "Medium"),
    (20, "Low"),
    (0, "Info"),
]

SEVERITY_RECOMMENDATIONS = {
    "Critical": [
        "Immediately block all associated IOCs (domains, IPs, URLs) at the network perimeter",
        "Issue fraud alert to all affected customer segments",
        "Escalate to incident response team for containment",
        "Submit sample to law enforcement cyber division",
        "Notify app stores for immediate takedown",
        "Review transaction logs for accounts that may have installed this APK",
    ],
    "High": [
        "Block identified malicious domains and IPs at firewall/proxy level",
        "Alert customers who may have been targeted",
        "Add YARA signatures to endpoint detection systems",
        "Monitor network traffic for C2 communication patterns",
        "Review and update fraud detection rules based on identified behavior",
    ],
    "Medium": [
        "Add identified indicators to threat intelligence watchlists",
        "Monitor for similar APK variants in the wild",
        "Update customer-facing security advisories",
        "Review app permissions against declared functionality",
    ],
    "Low": [
        "Log findings for trend analysis and future reference",
        "Monitor for escalation in capability or distribution",
        "Consider adding to greylist for enhanced monitoring",
    ],
    "Info": [
        "Archive report for baseline comparison",
        "No immediate action required",
    ],
}

DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS", "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG", "android.permission.CALL_PHONE",
    "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_PHONE_STATE", "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_DEVICE_ADMIN", "android.permission.READ_PHONE_NUMBERS",
    "android.permission.PROCESS_OUTGOING_CALLS", "android.permission.RECEIVE_BOOT_COMPLETED",
}


def _severity_label(score: float) -> str:
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "Info"


def _safe_get(data: Optional[dict], *keys, default=None):
    current = data or {}
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key, default)
        else:
            return default
    return current


def _build_apk_metadata(apk: APKUpload, static: dict) -> dict:
    package_name = _safe_get(static, "package_name") or _safe_get(static, "manifest", "package")
    return {
        "filename": apk.filename,
        "sha256": apk.sha256,
        "file_size": apk.file_size,
        "file_size_human": _human_size(apk.file_size) if apk.file_size else None,
        "upload_time": apk.upload_time.isoformat() if apk.upload_time else None,
        "package_name": package_name,
        "min_sdk": _safe_get(static, "min_sdk_version"),
        "target_sdk": _safe_get(static, "target_sdk_version"),
    }


def _human_size(size_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(size_bytes) < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def _extract_permissions(static: dict) -> dict:
    permissions = _safe_get(static, "permissions", default=[])
    if not isinstance(permissions, list):
        permissions = []
    dangerous = [p for p in permissions if p in DANGEROUS_PERMISSIONS]
    return {
        "total_count": len(permissions),
        "dangerous_count": len(dangerous),
        "dangerous_permissions": dangerous,
        "all_permissions": permissions,
    }


def _build_static_findings(static: dict) -> dict:
    permissions = _extract_permissions(static)
    return {
        "permissions": permissions,
        "suspicious_apis": _safe_get(static, "suspicious_apis", default=[]),
        "obfuscation_detected": _safe_get(static, "obfuscation_detected", default=False),
        "obfuscation_details": _safe_get(static, "obfuscation_details"),
        "dynamic_code_loading": _safe_get(static, "dynamic_code_loading", default=False),
        "native_code": _safe_get(static, "native_code", default=False),
        "reflection_usage": _safe_get(static, "reflection_usage", default=False),
        "crypto_usage": _safe_get(static, "crypto_usage"),
        "hardcoded_urls": _safe_get(static, "hardcoded_urls", default=[]),
        "hardcoded_ips": _safe_get(static, "hardcoded_ips", default=[]),
        "yara_matches": _safe_get(static, "yara_matches", default=[]),
        "certificate_info": _safe_get(static, "certificate_info"),
        "components": {
            "activities": _safe_get(static, "activities", default=[]),
            "services": _safe_get(static, "services", default=[]),
            "receivers": _safe_get(static, "receivers", default=[]),
            "providers": _safe_get(static, "providers", default=[]),
        },
    }


def _build_dynamic_findings(dynamic: dict) -> dict:
    return {
        "sms_interception": _safe_get(dynamic, "sms_interception", default=False),
        "accessibility_abuse": _safe_get(dynamic, "accessibility_abuse", default=False),
        "overlay_attacks": _safe_get(dynamic, "overlay_attacks", default=False),
        "keylogging": _safe_get(dynamic, "keylogging", default=False),
        "screen_capture": _safe_get(dynamic, "screen_capture", default=False),
        "device_admin_abuse": _safe_get(dynamic, "device_admin_abuse", default=False),
        "network_connections": _safe_get(dynamic, "network_connections", default=[]),
        "dns_queries": _safe_get(dynamic, "dns_queries", default=[]),
        "file_operations": _safe_get(dynamic, "file_operations", default=[]),
        "crypto_operations": _safe_get(dynamic, "crypto_operations", default=[]),
        "data_exfiltration": _safe_get(dynamic, "data_exfiltration"),
        "c2_communication": _safe_get(dynamic, "c2_communication"),
        "behavioral_summary": _safe_get(dynamic, "summary"),
    }


def _build_threat_intel(ti: dict, indicators: list) -> dict:
    matched_iocs = _safe_get(ti, "matched_iocs", default=[])
    malicious_domains = _safe_get(ti, "malicious_domains", default=[])
    malicious_ips = _safe_get(ti, "malicious_ips", default=[])
    malicious_urls = _safe_get(ti, "malicious_urls", default=[])
    sources = _safe_get(ti, "sources_consulted", default=[])

    for ind in indicators:
        matched_iocs.append({
            "type": ind.indicator_type,
            "value": ind.indicator_value,
            "source": ind.source,
            "severity": ind.severity,
        })

    return {
        "matched_iocs": matched_iocs,
        "total_ioc_matches": len(matched_iocs),
        "malicious_domains": malicious_domains,
        "malicious_ips": malicious_ips,
        "malicious_urls": malicious_urls,
        "sources_consulted": sources,
        "virustotal_detection": _safe_get(ti, "virustotal"),
        "abuse_ch_match": _safe_get(ti, "abuse_ch"),
    }


def _build_mitre_mappings(ti: dict, report: Optional[RiskReport]) -> list:
    if report and report.mitre_mappings:
        return report.mitre_mappings

    techniques = _safe_get(ti, "mitre_techniques", default=[])
    if isinstance(techniques, list):
        return techniques
    return []


def _build_fraud_analysis(report: Optional[RiskReport], fraud_data: dict) -> dict:
    return {
        "predicted_intent": (report.fraud_intent if report else None) or _safe_get(fraud_data, "intent"),
        "confidence": _safe_get(fraud_data, "confidence"),
        "fraud_category": _safe_get(fraud_data, "category"),
        "journey_stages": (report.fraud_journey if report else None) or _safe_get(fraud_data, "journey"),
        "target_victims": _safe_get(fraud_data, "target_victims"),
        "monetization_method": _safe_get(fraud_data, "monetization"),
    }


def _build_shap(report: Optional[RiskReport], score_data: dict) -> list:
    if report and report.shap_explanations:
        return report.shap_explanations

    shap = _safe_get(score_data, "shap_values", default=[])
    if isinstance(shap, list):
        return shap
    return []


def _build_risk_assessment(report: Optional[RiskReport], score_data: dict) -> dict:
    risk_score = (report.risk_score if report else None) or _safe_get(score_data, "score", default=0)
    severity = (report.severity if report else None) or _safe_get(score_data, "severity")
    if not severity:
        severity = _severity_label(risk_score or 0)

    classification = (report.classification if report else None) or _safe_get(score_data, "classification", default="Unknown")
    malware_family = _safe_get(score_data, "malware_family")
    class_probabilities = _safe_get(score_data, "class_probabilities")

    return {
        "risk_score": risk_score,
        "severity": severity,
        "classification": classification,
        "malware_family": malware_family,
        "class_probabilities": class_probabilities,
    }


def _generate_executive_summary(
    apk: APKUpload,
    risk: dict,
    static_findings: dict,
    dynamic_findings: dict,
    threat_intel_section: dict,
    fraud: dict,
) -> str:
    filename = apk.filename
    score = risk.get("risk_score", 0) or 0
    severity = risk.get("severity", "Unknown")
    classification = risk.get("classification", "Unknown")

    dangerous_count = static_findings.get("permissions", {}).get("dangerous_count", 0)
    ioc_count = threat_intel_section.get("total_ioc_matches", 0)
    yara_count = len(static_findings.get("yara_matches", []))

    behavioral_flags = []
    for flag in ("sms_interception", "accessibility_abuse", "overlay_attacks",
                 "keylogging", "screen_capture", "device_admin_abuse"):
        if dynamic_findings.get(flag):
            behavioral_flags.append(flag.replace("_", " "))

    network_count = len(dynamic_findings.get("network_connections", []))
    intent = fraud.get("predicted_intent") or "undetermined"

    parts = [
        f'The submitted APK "{filename}" has been classified as {classification} '
        f"with a risk score of {score:.0f}/100 ({severity} severity)."
    ]

    findings = []
    if dangerous_count:
        findings.append(f"{dangerous_count} dangerous Android permissions")
    if yara_count:
        findings.append(f"{yara_count} YARA rule match{'es' if yara_count != 1 else ''}")
    if ioc_count:
        findings.append(f"{ioc_count} known threat indicator{'s' if ioc_count != 1 else ''}")
    if static_findings.get("obfuscation_detected"):
        findings.append("code obfuscation techniques")
    if static_findings.get("dynamic_code_loading"):
        findings.append("dynamic code loading capability")

    if findings:
        parts.append(f"Static analysis identified {', '.join(findings)}.")

    if behavioral_flags:
        parts.append(
            f"Dynamic analysis revealed active {', '.join(behavioral_flags)} behavior"
            f"{f' with {network_count} outbound network connections' if network_count else ''}."
        )
    elif network_count:
        parts.append(f"Dynamic analysis detected {network_count} outbound network connections.")

    parts.append(f"The predicted attacker intent is {intent}.")

    if score >= 80:
        parts.append(
            "This APK poses an immediate threat and should be blocked across all channels. "
            "Incident response procedures should be initiated."
        )
    elif score >= 60:
        parts.append(
            "This APK represents a significant risk and warrants proactive blocking "
            "of associated indicators and customer notification."
        )
    elif score >= 40:
        parts.append("This APK should be monitored and its indicators added to watchlists.")
    else:
        parts.append("This APK presents limited risk but should be archived for reference.")

    return " ".join(parts)


def _generate_recommendations(severity: str, static_findings: dict, threat_intel_section: dict) -> list:
    base = SEVERITY_RECOMMENDATIONS.get(severity, SEVERITY_RECOMMENDATIONS["Info"])[:]

    if static_findings.get("yara_matches"):
        base.append("Investigate matched YARA signatures for malware family attribution")
    if static_findings.get("dynamic_code_loading"):
        base.append("Analyze dynamically loaded code for hidden payloads")
    if threat_intel_section.get("malicious_domains"):
        domains = threat_intel_section["malicious_domains"][:5]
        base.append(f"Block domains: {', '.join(domains)}")
    if threat_intel_section.get("malicious_ips"):
        ips = threat_intel_section["malicious_ips"][:5]
        base.append(f"Block IP addresses: {', '.join(ips)}")

    return base


def _compile_report(
    apk: APKUpload,
    analysis: Optional[AnalysisResult],
    indicators: list,
    existing_report: Optional[RiskReport],
) -> dict:
    static = (analysis.static_analysis if analysis else None) or {}
    dynamic = (analysis.dynamic_analysis if analysis else None) or {}
    ti = (analysis.threat_intel if analysis else None) or {}

    score_data = {}
    fraud_data = {}
    if existing_report:
        score_data = {
            "score": existing_report.risk_score,
            "severity": existing_report.severity,
            "classification": existing_report.classification,
            "shap_values": existing_report.shap_explanations,
        }
        fraud_data = {
            "intent": existing_report.fraud_intent,
            "journey": existing_report.fraud_journey,
        }

    metadata = _build_apk_metadata(apk, static)
    risk = _build_risk_assessment(existing_report, score_data)
    static_findings = _build_static_findings(static)
    dynamic_findings = _build_dynamic_findings(dynamic)
    threat_intel_section = _build_threat_intel(ti, indicators)
    mitre = _build_mitre_mappings(ti, existing_report)
    fraud = _build_fraud_analysis(existing_report, fraud_data)
    shap = _build_shap(existing_report, score_data)

    executive_summary = _generate_executive_summary(
        apk, risk, static_findings, dynamic_findings, threat_intel_section, fraud
    )
    recommendations = _generate_recommendations(
        risk.get("severity", "Info"), static_findings, threat_intel_section
    )

    is_complete = apk.status == "completed" and analysis is not None

    return {
        "apk_id": str(apk.id),
        "report_status": "complete" if is_complete else "partial",
        "generated_at": datetime.utcnow().isoformat(),
        "executive_summary": executive_summary,
        "apk_metadata": metadata,
        "risk_assessment": risk,
        "static_analysis": static_findings,
        "dynamic_analysis": dynamic_findings,
        "threat_intelligence": threat_intel_section,
        "mitre_attack_mappings": mitre,
        "fraud_intent_analysis": fraud,
        "shap_explainability": shap,
        "recommendations": recommendations,
        "ai_summary": analysis.ai_summary if analysis else None,
    }


def _persist_report(db: Session, apk_id: str, compiled: dict) -> RiskReport:
    report = RiskReport(
        apk_id=apk_id,
        risk_score=compiled["risk_assessment"].get("risk_score"),
        severity=compiled["risk_assessment"].get("severity"),
        classification=compiled["risk_assessment"].get("classification"),
        fraud_intent=compiled["fraud_intent_analysis"].get("predicted_intent"),
        fraud_journey=compiled["fraud_intent_analysis"].get("journey_stages"),
        executive_summary=compiled["executive_summary"],
        recommendations=compiled["recommendations"],
        mitre_mappings=compiled["mitre_attack_mappings"],
        shap_explanations=compiled["shap_explainability"],
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


@router.get("/{apk_id}")
def get_report(apk_id: str, db: Session = Depends(get_db)):
    apk = db.query(APKUpload).filter(APKUpload.id == apk_id).first()
    if not apk:
        raise HTTPException(status_code=404, detail="APK not found")

    analysis = db.query(AnalysisResult).filter(AnalysisResult.apk_id == apk_id).first()
    existing_report = db.query(RiskReport).filter(RiskReport.apk_id == apk_id).first()
    indicators = db.query(ThreatIndicator).filter(ThreatIndicator.apk_id == apk_id).all()

    if apk.status in ("pending", "processing") and not analysis:
        raise HTTPException(status_code=202, detail="Analysis still in progress")

    if existing_report and apk.status == "completed":
        compiled = _compile_report(apk, analysis, indicators, existing_report)
        compiled["report_id"] = str(existing_report.id)
        compiled["created_at"] = existing_report.created_at.isoformat() if existing_report.created_at else None
        return compiled

    compiled = _compile_report(apk, analysis, indicators, existing_report)

    if apk.status == "completed" and not existing_report:
        saved = _persist_report(db, apk_id, compiled)
        compiled["report_id"] = str(saved.id)
        compiled["created_at"] = saved.created_at.isoformat() if saved.created_at else None

    return compiled


@router.get("/{apk_id}/summary")
def get_report_summary(apk_id: str, db: Session = Depends(get_db)):
    apk = db.query(APKUpload).filter(APKUpload.id == apk_id).first()
    if not apk:
        raise HTTPException(status_code=404, detail="APK not found")

    report = db.query(RiskReport).filter(RiskReport.apk_id == apk_id).first()
    if not report:
        if apk.status in ("pending", "processing"):
            raise HTTPException(status_code=202, detail="Analysis still in progress")
        raise HTTPException(status_code=404, detail="Report not generated yet")

    return {
        "apk_id": str(apk.id),
        "filename": apk.filename,
        "risk_score": report.risk_score,
        "severity": report.severity,
        "classification": report.classification,
        "executive_summary": report.executive_summary,
        "created_at": report.created_at,
    }


@router.get("/{apk_id}/pdf")
def download_pdf(apk_id: str, db: Session = Depends(get_db)):
    report = db.query(RiskReport).filter(RiskReport.apk_id == apk_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"message": "PDF generation not yet implemented", "apk_id": apk_id}

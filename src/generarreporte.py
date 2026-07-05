import json
import os
import uuid
from datetime import datetime

import boto3

lambda_client = boto3.client("lambda")

REPORT_FORMAT_TEMPLATE = """
=== REPORTE EJECUTIVO DE SEGURIDAD XOC ===

CLIENTE: {tenant_id}
FECHA DE GENERACION: {fecha}
SOFTWARES INCLUIDOS: {softwares_list}
PERIODO DEL REPORTE: {periodo}

--- 1. DATOS DE MONITOREO Y VULNERABILIDADES ---
{detalle_softwares}

--- 2. COMPARATIVA DE VULNERABILIDADES (PERIODO ANTERIOR vs ACTUAL) ---
{analisis_vulnerabilidades}

--- 3. ESTADO DE MONITOREO NOC ---
{estado_monitoreo}

--- 4. DETALLE DE HOSTS Y SERVIDORES ---
{detalle_hosts}

--- 5. HALLAZGOS CRITICOS DETALLADOS ---
{hallazgos_detallados}

--- 6. INFORMACION DE SEGURIDAD ADICIONAL ---
{informacion_adicional}

--- 7. RECOMENDACIONES INICIALES ---
{recomendaciones}

--- 8. CONCLUSIONES PRELIMINARES ---
{conclusiones}

INDICACIONES DEL CLIENTE: {indicaciones_cliente}
"""


def _build_software_list(sw: dict) -> str:
    enabled = [k.upper() for k, v in sw.items() if v]
    return ", ".join(enabled) if enabled else "Ninguno"


def _format_finding(f: dict) -> str:
    lines = [
        f"  * {f.get('name', 'N/A')}",
        f"    Severidad: {f.get('severity', 'N/A').upper()} | CVSS: {f.get('cvss', 'N/A')} | CVE: {f.get('cve', 'N/A')}",
        f"    Host: {f.get('host', 'N/A')} | Puerto: {f.get('port', 'N/A')}/{f.get('protocol', 'N/A')}",
        f"    Descripcion: {f.get('description', 'N/A')}",
        f"    Solucion: {f.get('solution', 'N/A')}",
    ]
    return "\n".join(lines)


def _format_mock_data_for_prompt(software: str, data: dict) -> str:
    lines = []
    if software == "zabbix":
        lines.append(f"[ZABBIX - MONITOREO NOC]")
        lines.append(f"  Hosts monitoreados: {data.get('hosts_monitored', 0)}")
        lines.append(f"  Alertas activas totales: {data.get('alerts', 0)}")
        alerts_sev = data.get("alerts_by_severity", {})
        lines.append(f"  Alertas por severidad: Disaster={alerts_sev.get('disaster',0)} High={alerts_sev.get('high',0)} Average={alerts_sev.get('average',0)} Warning={alerts_sev.get('warning',0)}")
        lines.append(f"  Hosts por ubicacion: {data.get('hosts_by_location', {})}")
        lines.append(f"  CPU promedio: {data.get('avg_cpu', 0)}% | RAM promedio: {data.get('avg_ram', 0)}% | Disco promedio: {data.get('avg_disk', 0)}%")
        lines.append(f"  Uptime general: {data.get('uptime_percentage', 0)}%")
        lines.append(f"  Top CPU: {data.get('top_cpu_hosts', [])}")
        lines.append(f"  Alertas recientes:")
        for a in data.get("recent_alerts", []):
            lines.append(f"    - [{a.get('severity','').upper()}] {a.get('name','N/A')}: {a.get('description','N/A')} (duracion: {a.get('duration_minutes',0)} min)")

    elif software == "uptime_kuma":
        lines.append(f"[UPTIME KUMA - DISPONIBILIDAD DE SERVICIOS]")
        svc = data.get("services", {})
        lines.append(f"  Servicios: {svc.get('total', 0)} totales | {svc.get('up', 0)} UP | {svc.get('down', 1)} DOWN | {svc.get('pending', 0)} PENDING")
        lines.append(f"  Uptime global: {data.get('uptime_percentage', 0)}%")
        lines.append(f"  Incidentes en 30d: {data.get('incidents_30d', 0)} | Tiempo caida total: {data.get('total_outage_minutes_30d', 0)} min")
        lines.append(f"  Detalle por servicio:")
        for s in data.get("services_detail", []):
            lines.append(f"    - {s.get('name','N/A')}: {s.get('status','N/A')} (uptime 30d: {s.get('uptime_30d',0)}%, respuesta: {s.get('response_time_ms',0)}ms)")

    elif software in ("nessus", "openvas", "insightvm"):
        lines.append(f"[{software.upper()} - ESCANEO DE VULNERABILIDADES]")
        vulns = data.get("vulnerabilities", {})
        lines.append(f"  Vulnerabilidades: Critical={vulns.get('critical',0)} High={vulns.get('high',0)} Medium={vulns.get('medium',0)} Low={vulns.get('low',0)} Info={vulns.get('info',0)}")
        lines.append(f"  Total hosts escaneados: {data.get('hosts_scanned', 0)}")
        lines.append(f"  Risk Score: {data.get('risk_score', 0)}")
        prev = data.get("previous_period", {})
        lines.append(f"  Periodo anterior: Critical={prev.get('critical',0)} High={prev.get('high',0)} Medium={prev.get('medium',0)} Low={prev.get('low',0)} Info={prev.get('info',0)}")
        lines.append(f"  Top CVEs:")
        for c in data.get("top_cves", []):
            lines.append(f"    - {c.get('cve','N/A')} (CVSS {c.get('cvss','N/A')}): {c.get('name','N/A')} - {c.get('affected',0)} hosts afectados")
        lines.append(f"  Detalle de hosts escaneados:")
        for h in data.get("hosts_detail", []):
            lines.append(f"    - {h.get('ip','N/A')} ({h.get('hostname','N/A')}) OS: {h.get('os','N/A')} Servicios: {', '.join(h.get('services',[]))}")
        lines.append(f"  Hallazgos recientes:")
        for f in data.get("recent_findings", []):
            lines.append(_format_finding(f))

    elif software == "wazuh":
        lines.append(f"[WAZUH - SIEM & DETECCION DE AMENAZAS]")
        alerts = data.get("alerts", {})
        lines.append(f"  Alertas totales: {alerts.get('total', 0)}")
        lines.append(f"  Alertas por severidad: Critical={alerts.get('critical',0)} High={alerts.get('high',0)} Medium={alerts.get('medium',0)} Low={alerts.get('low',0)}")
        lines.append(f"  Alertas por categoria: {data.get('alerts_by_category', {})}")
        agents = data.get("agents", {})
        lines.append(f"  Agentes: {agents.get('total', 0)} totales | {agents.get('active', 0)} activos | {agents.get('disconnected', 0)} desconectados")
        lines.append(f"  Agentes por SO: {data.get('agents_by_os', {})}")
        lines.append(f"  Estado del manager: {data.get('manager_status', 'N/A')}")
        lines.append(f"  Ultimo ataque detectado: {data.get('last_attack_detected', 'N/A')}")
        lines.append(f"  Eventos principales:")
        for e in data.get("top_events", []):
            lines.append(f"    - [{e.get('severity','').upper()}] {e.get('description','N/A')} ({e.get('count',0)} ocurrencias)")
        compliance = data.get("compliance_status", {})
        lines.append(f"  Cumplimiento normativo: PCI DSS {compliance.get('pci_dss',0)}% | ISO 27001 {compliance.get('iso_27001',0)}% | NIST {compliance.get('nist',0)}%")

    return "\n".join(lines) if lines else f"  {software.upper()}: Sin datos disponibles"


def _build_analytics_prompt(sw: dict, analytics_data: dict) -> str:
    sections = []
    for sw_name, enabled in sw.items():
        if enabled and sw_name in analytics_data.get("data", {}):
            sections.append(_format_mock_data_for_prompt(sw_name, analytics_data["data"][sw_name]))
    return "\n\n".join(sections) if sections else "  (No hay datos de software habilitados)"


def _build_vuln_analysis(sw: dict, analytics_data: dict) -> str:
    vuln_sw = [s for s in ("nessus", "openvas", "insightvm") if sw.get(s)]
    if not vuln_sw:
        return "Sin software de vulnerabilidades habilitado."
    lines = []
    for s in vuln_sw:
        data = analytics_data.get("data", {}).get(s, {})
        v = data.get("vulnerabilities", {})
        p = data.get("previous_period", {})
        lines.append(f"  [{s.upper()}]")
        lines.append(f"    Periodo actual: C={v.get('critical',0)} H={v.get('high',0)} M={v.get('medium',0)} L={v.get('low',0)} I={v.get('info',0)}")
        lines.append(f"    Periodo anterior: C={p.get('critical',0)} H={p.get('high',0)} M={p.get('medium',0)} L={p.get('low',0)} I={p.get('info',0)}")
        for nivel in ("critical", "high", "medium", "low", "info"):
            act = v.get(nivel, 0)
            ant = p.get(nivel, 0)
            diff = act - ant
            signo = "+" if diff > 0 else ""
            lines.append(f"    Variacion {nivel}: {signo}{diff}")
    return "\n".join(lines)


def _build_monitoring_status(sw: dict, analytics_data: dict) -> str:
    noc_sw = [s for s in ("zabbix", "uptime_kuma") if sw.get(s)]
    if not noc_sw:
        return "Sin software de monitoreo habilitado."
    lines = []
    for s in noc_sw:
        data = analytics_data.get("data", {}).get(s, {})
        if s == "zabbix":
            lines.append(f"  [ZABBIX] {data.get('hosts_monitored', 0)} hosts, {data.get('alerts', 0)} alertas activas, CPU {data.get('avg_cpu',0)}% / RAM {data.get('avg_ram',0)}%")
            for a in data.get("recent_alerts", []):
                lines.append(f"    - {a.get('name','N/A')}: {a.get('description','N/A')}")
        elif s == "uptime_kuma":
            svc = data.get("services", {})
            lines.append(f"  [UPTIME KUMA] {svc.get('up', 0)} UP / {svc.get('down', 0)} DOWN de {svc.get('total', 0)} servicios (uptime: {data.get('uptime_percentage',0)}%)")
            for sd in data.get("services_detail", []):
                if sd.get("status") != "up":
                    lines.append(f"    - {sd.get('name','N/A')}: {sd.get('status','N/A')} (uptime 30d: {sd.get('uptime_30d',0)}%)")
    return "\n".join(lines)


def _build_hosts_detail(sw: dict, analytics_data: dict) -> str:
    vuln_sw = [s for s in ("nessus", "openvas", "insightvm") if sw.get(s)]
    if not vuln_sw:
        return "Sin datos de hosts disponibles."
    lines = []
    for s in vuln_sw:
        data = analytics_data.get("data", {}).get(s, {})
        hosts = data.get("hosts_detail", [])
        if hosts:
            lines.append(f"  [{s.upper()} - HOSTS ESCANEADOS]")
            for h in hosts:
                lines.append(f"    - {h.get('ip','N/A')} / {h.get('hostname','N/A')} | SO: {h.get('os','N/A')} | Servicios: {', '.join(h.get('services',[]))}")
    return "\n".join(lines)


def _build_detailed_findings(sw: dict, analytics_data: dict) -> str:
    vuln_sw = [s for s in ("nessus", "openvas", "insightvm") if sw.get(s)]
    if not vuln_sw:
        return "Sin hallazgos disponibles."
    lines = []
    for s in vuln_sw:
        data = analytics_data.get("data", {}).get(s, {})
        findings = data.get("recent_findings", [])
        if findings:
            lines.append(f"  [{s.upper()} - HALLAZGOS DETALLADOS]")
            for f in findings:
                lines.append(_format_finding(f))
    return "\n".join(lines)


def _build_additional_info(sw: dict, analytics_data: dict) -> str:
    parts = []
    # Wazuh SIEM info
    if sw.get("wazuh"):
        w = analytics_data.get("data", {}).get("wazuh", {})
        events = w.get("top_events", [])
        if events:
            parts.append("[WAZUH - EVENTOS DE SEGURIDAD DESTACADOS]")
            for e in events:
                parts.append(f"  - {e.get('description','N/A')}: {e.get('count',0)} ocurrencias (severidad: {e.get('severity','N/A')})")
        compliance = w.get("compliance_status", {})
        if compliance:
            parts.append(f"[CUMPLIMIENTO NORMATIVO] PCI DSS: {compliance.get('pci_dss',0)}% | ISO 27001: {compliance.get('iso_27001',0)}% | NIST: {compliance.get('nist',0)}%")
    # Uptime Kuma detail
    if sw.get("uptime_kuma"):
        uk = analytics_data.get("data", {}).get("uptime_kuma", {})
        svc = uk.get("services_detail", [])
        if svc:
            parts.append("[UPTIME KUMA - ESTADO COMPLETO DE SERVICIOS]")
            for s in svc:
                parts.append(f"  - {s.get('name','N/A')}: {s.get('status','N/A')} (uptime 30d: {s.get('uptime_30d',0)}%, latencia: {s.get('response_time_ms',0)}ms)")
    return "\n".join(parts) if parts else "Sin informacion adicional disponible."


def _invoke_analytics(softwares: dict, tenant_id: str, indicaciones: str) -> dict:
    nombre_funcion = os.environ.get("ANALYTICS_REAL_FUNCTION", "Analytics")
    try:
        resp = lambda_client.invoke(
            FunctionName=nombre_funcion,
            InvocationType="RequestResponse",
            Payload=json.dumps({"tenant_id": tenant_id, "softwares": softwares, "indicaciones": indicaciones}),
        )
        payload = json.loads(resp["Payload"].read())
        if isinstance(payload, dict) and "body" in payload:
            return json.loads(payload["body"])
        return payload
    except Exception as e:
        nombre_mock = os.environ.get("ANALYTICS_MOCK_FUNCTION")
        if nombre_mock:
            resp = lambda_client.invoke(
                FunctionName=nombre_mock,
                InvocationType="RequestResponse",
                Payload=json.dumps({"tenant_id": tenant_id, "softwares": softwares, "indicaciones": indicaciones}),
            )
            return json.loads(resp["Payload"].read())
        return {"tenant_id": tenant_id, "data": {}, "generated_at": datetime.utcnow().isoformat(), "fallback": True, "error": str(e)}


def _invoke_transia_xml(contenido_reporte: str, indicaciones: str, tenant_id: str, softwares_list: str = "") -> dict:
    nombre_funcion = os.environ.get("TRANSIA_XML_FUNCTION")
    if not nombre_funcion:
        raise RuntimeError("TRANSIA_XML_FUNCTION no configurada")
    resp = lambda_client.invoke(
        FunctionName=nombre_funcion,
        InvocationType="RequestResponse",
        Payload=json.dumps({"contenido_reporte": contenido_reporte, "indicaciones": indicaciones, "tenant_id": tenant_id, "softwares_list": softwares_list}),
    )
    return json.loads(resp["Payload"].read())


def handler(event, context):
    try:
        if isinstance(event.get("body"), str):
            body = json.loads(event["body"])
        else:
            body = event.get("body", event)

        softwares = {
            "zabbix": bool(body.get("zabbix", False)),
            "openvas": bool(body.get("openvas", False)),
            "insightvm": bool(body.get("insightvm", False)),
            "wazuh": bool(body.get("wazuh", False)),
            "nessus": bool(body.get("nessus", False)),
            "uptime_kuma": bool(body.get("uptime_kuma", False)),
        }
        indicaciones = str(body.get("indicaciones", ""))
        tenant_id = str(body.get("tenant_id", "tenant-unknown"))
        reporte_id = str(uuid.uuid4())

        if not any(softwares.values()):
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
                "body": json.dumps({"success": False, "error": "Debe habilitar al menos un software"}),
            }

        analytics_data = _invoke_analytics(softwares, tenant_id, indicaciones)

        detalle = _build_analytics_prompt(softwares, analytics_data)
        vuln_analysis = _build_vuln_analysis(softwares, analytics_data)
        monitoring = _build_monitoring_status(softwares, analytics_data)
        hosts_detail = _build_hosts_detail(softwares, analytics_data)
        findings_detailed = _build_detailed_findings(softwares, analytics_data)
        additional_info = _build_additional_info(softwares, analytics_data)
        sw_list = _build_software_list(softwares)

        contenido_reporte = REPORT_FORMAT_TEMPLATE.format(
            tenant_id=tenant_id,
            fecha=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            softwares_list=sw_list,
            periodo=datetime.utcnow().strftime("Del 01 al %d de %B de %Y"),
            detalle_softwares=detalle,
            analisis_vulnerabilidades=vuln_analysis,
            estado_monitoreo=monitoring,
            detalle_hosts=hosts_detail,
            hallazgos_detallados=findings_detailed,
            informacion_adicional=additional_info,
            recomendaciones="Pendiente de generacion por IA.",
            conclusiones="Pendiente de generacion por IA.",
            indicaciones_cliente=indicaciones if indicaciones else "Generar reporte ejecutivo completo de seguridad.",
        )

        resultado = _invoke_transia_xml(contenido_reporte, indicaciones, tenant_id, sw_list)

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
            "body": json.dumps(
                {
                    "success": True,
                    "reporte_id": reporte_id,
                    "tenant_id": tenant_id,
                    "softwares_incluidos": sw_list,
                    "analytics_data_obtenida": bool(analytics_data.get("data")),
                    "resultado_xml": resultado,
                }
            ),
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"success": False, "error": str(e), "reporte_id": None}),
        }

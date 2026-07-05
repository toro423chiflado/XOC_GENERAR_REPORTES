import json
import os
import uuid
from datetime import datetime

import boto3

lambda_client = boto3.client("lambda")

REPORT_FORMAT_TEMPLATE = """
REPORTE DE SEGURIDAD XOC
========================

1. METADATOS DEL REPORTE
   - Titulo: {titulo}
   - Fecha de generacion: {fecha}
   - Tenant ID: {tenant_id}
   - Softwares incluidos: {softwares_list}

2. RESUMEN EJECUTIVO
   {resumen_ejecutivo}

3. DETALLE POR SOFTWARE
{detalle_softwares}

4. ANALISIS DE VULNERABILIDADES
   {analisis_vulnerabilidades}

5. ESTADO DE MONITOREO (NOC)
   {estado_monitoreo}

6. CONCLUSIONES
   {conclusiones}

7. RECOMENDACIONES
   {recomendaciones}
"""


def _build_software_list(sw: dict) -> str:
    enabled = [k.upper() for k, v in sw.items() if v]
    return ", ".join(enabled) if enabled else "Ninguno"


def _format_mock_data_for_prompt(software: str, data: dict) -> str:
    if software == "zabbix":
        hosts = data.get("hosts_monitored", 0)
        alerts = data.get("alerts", 0)
        cpu = data.get("avg_cpu", 0)
        ram = data.get("avg_ram", 0)
        return f"  ZABBIX (Monitoreo NOC):\n    Hosts monitoreados: {hosts}\n    Alertas activas: {alerts}\n    CPU promedio: {cpu}%\n    RAM promedio: {ram}%"
    elif software == "uptime_kuma":
        svc = data.get("services", {})
        uptime = data.get("uptime_percentage", 0)
        return f"  UPTIME KUMA (Disponibilidad):\n    Servicios totales: {svc.get('total', 0)}\n    Up: {svc.get('up', 0)}\n    Down: {svc.get('down', 0)}\n    Uptime: {uptime}%"
    elif software in ("nessus", "openvas", "insightvm"):
        vulns = data.get("vulnerabilities", {})
        vuln_total = sum(vulns.values())
        scans = data.get("recent_scans", [])
        scan_info = ""
        if scans:
            s = scans[0]
            scan_info = f"    Ultimo scan: {s.get('scan_name', 'N/A')} - {s.get('status', 'N/A')}"
        findings = data.get("recent_findings", [])
        top = ""
        for f in findings[:3]:
            top += f"      - {f.get('name', 'N/A')} | {f.get('severity', 'N/A')} | CVSS: {f.get('cvss', 'N/A')}\n"
        return f"  {software.upper()} (Vulnerabilidades):\n    Totales: C={vulns.get('critical',0)} H={vulns.get('high',0)} M={vulns.get('medium',0)} L={vulns.get('low',0)} I={vulns.get('info',0)}\n    Total vulnerabilidades: {vuln_total}\n{scan_info}\n    Hallazgos recientes:\n{top}"
    elif software == "wazuh":
        alerts = data.get("alerts", {})
        alerts_total = alerts.get("total", 0)
        agents = data.get("agents", {})
        return f"  WAZUH (SIEM):\n    Alertas totales: {alerts_total}\n    Agentes: {agents.get('total', 0)} activos, {agents.get('disconnected', 0)} desconectados\n    Estado del manager: {data.get('manager_status', 'N/A')}"
    return f"  {software.upper()}: Sin datos disponibles"


def _build_analytics_prompt(sw: dict, analytics_data: dict) -> str:
    sections = []
    for sw_name, enabled in sw.items():
        if enabled and sw_name in analytics_data.get("data", {}):
            sections.append(_format_mock_data_for_prompt(sw_name, analytics_data["data"][sw_name]))
    return "\n".join(sections) if sections else "  (No hay datos de software habilitados)"


def _build_vuln_analysis(sw: dict, analytics_data: dict) -> str:
    vuln_sw = [s for s in ("nessus", "openvas", "insightvm") if sw.get(s)]
    if not vuln_sw:
        return "Sin software de vulnerabilidades habilitado."
    lines = []
    for s in vuln_sw:
        data = analytics_data.get("data", {}).get(s, {})
        v = data.get("vulnerabilities", {})
        lines.append(f"  - {s.upper()}: {sum(v.values())} total (C={v.get('critical',0)} H={v.get('high',0)} M={v.get('medium',0)} L={v.get('low',0)} I={v.get('info',0)})")
    return "\n".join(lines)


def _build_monitoring_status(sw: dict, analytics_data: dict) -> str:
    noc_sw = [s for s in ("zabbix", "uptime_kuma") if sw.get(s)]
    if not noc_sw:
        return "Sin software de monitoreo habilitado."
    lines = []
    for s in noc_sw:
        data = analytics_data.get("data", {}).get(s, {})
        if s == "zabbix":
            lines.append(f"  - ZABBIX: {data.get('hosts_monitored', 0)} hosts, {data.get('alerts', 0)} alertas")
        elif s == "uptime_kuma":
            svc = data.get("services", {})
            lines.append(f"  - UPTIME KUMA: {svc.get('up', 0)} up / {svc.get('down', 0)} down de {svc.get('total', 0)} servicios")
    return "\n".join(lines)


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
        sw_list = _build_software_list(softwares)

        contenido_reporte = REPORT_FORMAT_TEMPLATE.format(
            titulo=f"Reporte XOC - {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC",
            fecha=datetime.utcnow().isoformat(),
            tenant_id=tenant_id,
            softwares_list=sw_list,
            resumen_ejecutivo=indicaciones if indicaciones else "Reporte generado automaticamente por XOC API.",
            detalle_softwares=detalle,
            analisis_vulnerabilidades=vuln_analysis,
            estado_monitoreo=monitoring,
            conclusiones="Pendiente de revision por el equipo de seguridad.",
            recomendaciones="- Revisar vulnerabilidades criticas.\n- Verificar estado de agentes.\n- Validar monitoreo continuo.",
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

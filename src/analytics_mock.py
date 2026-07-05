import json
import random
from datetime import datetime, timedelta


def _mock_nessus_openvas(scanner: str) -> dict:
    return {
        "configured": True,
        "active": True,
        "has_data": True,
        "last_sync": datetime.utcnow().isoformat(),
        "scans": {
            "total": 12,
            "completed": 10,
            "running": 2,
            "scans": [
                {
                    "id": 1501,
                    "scan_id": f"{scanner}-scan-001",
                    "scan_name": f"{scanner.upper()} Weekly Scan",
                    "status": "completed",
                    "scanned_at": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
                    "critical_count": 5,
                    "high_count": 11,
                    "medium_count": 16,
                    "low_count": 24,
                    "info_count": 32,
                    "total_hosts": 42,
                    "cvss_max": 9.8,
                }
            ],
        },
        "vulnerabilities": {"critical": 5, "high": 11, "medium": 16, "low": 24, "info": 32},
        "hosts_scanned": 42,
        "recent_findings": [
            {
                "id": f"{scanner}-f-1",
                "name": f"Remote Code Execution in Apache ({scanner.upper()})",
                "severity": "critical",
                "cvss": 9.8,
                "cve": "CVE-2025-1201",
                "host": "192.168.1.15",
                "port": "443",
                "protocol": "tcp",
                "description": "Vulnerabilidad critica de RCE en Apache HTTP Server.",
                "solution": "Aplicar parche de seguridad mas reciente.",
            },
            {
                "id": f"{scanner}-f-2",
                "name": f"OpenSSL Heartbleed-like ({scanner.upper()})",
                "severity": "high",
                "cvss": 7.5,
                "cve": "CVE-2025-1207",
                "host": "192.168.1.22",
                "port": "443",
                "protocol": "tcp",
                "description": "Fuga de memoria en OpenSSL.",
                "solution": "Actualizar OpenSSL a version 3.x.",
            },
            {
                "id": f"{scanner}-f-3",
                "name": f"Default Credentials on MySQL ({scanner.upper()})",
                "severity": "high",
                "cvss": 7.2,
                "cve": "CVE-2025-1215",
                "host": "192.168.1.30",
                "port": "3306",
                "protocol": "tcp",
                "description": "Credenciales por defecto en base de datos MySQL.",
                "solution": "Cambiar credenciales y desactivar acceso remoto.",
            },
        ],
        "agent_name": f"{scanner.upper()}-AGENT-MOCK",
    }


def _mock_zabbix() -> dict:
    return {
        "configured": True,
        "active": True,
        "has_data": True,
        "last_sync": datetime.utcnow().isoformat(),
        "alerts": 8,
        "hosts_monitored": 24,
        "avg_cpu": 45.2,
        "avg_ram": 62.8,
        "recent_alerts": [
            {
                "name": "CPU high on srv-web-01",
                "severity": "high",
                "event_type": "trigger",
                "status": "PROBLEM",
                "host": "srv-web-01",
                "service": "CPU",
                "description": "CPU > 90% durante 10 minutos",
                "started_at": (datetime.utcnow() - timedelta(minutes=15)).isoformat(),
            },
            {
                "name": "Disk space low on srv-db-01",
                "severity": "high",
                "event_type": "trigger",
                "status": "PROBLEM",
                "host": "srv-db-01",
                "service": "Disk",
                "description": "Disco /data al 85%",
                "started_at": (datetime.utcnow() - timedelta(hours=1)).isoformat(),
            },
        ],
        "agent_name": "ZABBIX-AGENT-MOCK",
    }


def _mock_wazuh() -> dict:
    return {
        "configured": True,
        "active": True,
        "has_data": True,
        "last_sync": datetime.utcnow().isoformat(),
        "alerts": {"total": 156, "critical": 3, "high": 9, "medium": 14, "low": 22, "info": 30, "recent": []},
        "agents": {"total": 18, "active": 15, "disconnected": 2, "never_connected": 1},
        "manager_status": "healthy",
        "agent_name": "WAZUH-AGENT-MOCK",
    }


def _mock_uptime_kuma() -> dict:
    return {
        "configured": True,
        "active": True,
        "has_data": True,
        "last_sync": datetime.utcnow().isoformat(),
        "services": {"total": 12, "up": 10, "down": 1, "pending": 1},
        "uptime_percentage": 99.12,
        "status": "degraded",
        "agent_name": "UPTIMEKUMA-AGENT-MOCK",
    }


def handler(event, context):
    try:
        if isinstance(event.get("body"), str):
            body = json.loads(event["body"])
        else:
            body = event

        softwares = body.get("softwares", {})
        tenant_id = body.get("tenant_id", "tenant-unknown")

        data = {}
        if softwares.get("zabbix"):
            data["zabbix"] = _mock_zabbix()
        if softwares.get("openvas"):
            data["openvas"] = _mock_nessus_openvas("openvas")
        if softwares.get("insightvm"):
            data["insightvm"] = _mock_nessus_openvas("insightvm")
        if softwares.get("nessus"):
            data["nessus"] = _mock_nessus_openvas("nessus")
        if softwares.get("wazuh"):
            data["wazuh"] = _mock_wazuh()
        if softwares.get("uptime_kuma"):
            data["uptime_kuma"] = _mock_uptime_kuma()

        return {
            "tenant_id": tenant_id,
            "generated_at": datetime.utcnow().isoformat(),
            "data": data,
        }

    except Exception as e:
        return {"tenant_id": body.get("tenant_id", "unknown"), "error": str(e), "data": {}}

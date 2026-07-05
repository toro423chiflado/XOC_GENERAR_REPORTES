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
                    "scan_name": f"{scanner.upper()} Weekly Vulnerability Scan",
                    "status": "completed",
                    "scanned_at": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
                    "critical_count": 5,
                    "high_count": 11,
                    "medium_count": 16,
                    "low_count": 24,
                    "info_count": 32,
                    "total_hosts": 42,
                    "cvss_max": 9.8,
                    "scan_duration_minutes": 47,
                }
            ],
        },
        "vulnerabilities": {"critical": 5, "high": 11, "medium": 16, "low": 24, "info": 32},
        "previous_period": {"critical": 8, "high": 14, "medium": 18, "low": 22, "info": 28},
        "hosts_scanned": 42,
        "hosts_detail": [
            {"ip": "192.168.1.10", "hostname": "srv-web-01", "os": "Ubuntu 22.04 LTS", "services": ["HTTP/443", "SSH/22"]},
            {"ip": "192.168.1.15", "hostname": "srv-web-02", "os": "CentOS 7", "services": ["HTTP/443", "SSH/22", "MySQL/3306"]},
            {"ip": "192.168.1.20", "hostname": "srv-app-01", "os": "Windows Server 2022", "services": ["IIS/443", "RDP/3389"]},
            {"ip": "192.168.1.22", "hostname": "srv-app-02", "os": "Windows Server 2019", "services": ["IIS/443", "MSSQL/1433"]},
            {"ip": "192.168.1.25", "hostname": "fw-core-01", "os": "FortiOS 7.4", "services": ["HTTPS/443", "SSH/22"]},
        ],
        "risk_score": 72.4,
        "top_cves": [
            {"cve": "CVE-2025-1201", "cvss": 9.8, "name": "Remote Code Execution in Apache HTTP Server", "affected": 3},
            {"cve": "CVE-2025-1207", "cvss": 7.5, "name": "OpenSSL Memory Information Disclosure", "affected": 5},
            {"cve": "CVE-2025-1215", "cvss": 7.2, "name": "MySQL Default Credentials Vulnerability", "affected": 2},
            {"cve": "CVE-2025-1220", "cvss": 6.5, "name": "SMBv3 Remote Code Execution", "affected": 4},
            {"cve": "CVE-2025-1189", "cvss": 5.4, "name": "Apache Tomcat Path Traversal", "affected": 2},
        ],
        "recent_findings": [
            {
                "id": f"{scanner}-f-1",
                "name": "Remote Code Execution in Apache HTTP Server",
                "severity": "critical",
                "cvss": 9.8,
                "cve": "CVE-2025-1201",
                "host": "192.168.1.15",
                "port": "443",
                "protocol": "tcp",
                "description": "Se detectó una vulnerabilidad crítica de ejecución remota de código en Apache HTTP Server que permite a un atacante no autenticado tomar control total del servidor mediante una solicitud HTTP especialmente diseñada.",
                "solution": "Aplicar el parche de seguridad más reciente proporcionado por Apache Software Foundation. Como mitigación temporal, deshabilitar módulos innecesarios y restringir el acceso por firewall.",
                "exploit_available": True,
            },
            {
                "id": f"{scanner}-f-2",
                "name": "OpenSSL Memory Information Disclosure",
                "severity": "high",
                "cvss": 7.5,
                "cve": "CVE-2025-1207",
                "host": "192.168.1.22",
                "port": "443",
                "protocol": "tcp",
                "description": "Se identificó una vulnerabilidad de divulgación de memoria en OpenSSL que permite a un atacante remoto recuperar fragmentos de memoria del servidor, potencialmente exponiendo datos sensibles como claves privadas o credenciales.",
                "solution": "Actualizar OpenSSL a la versión 3.x más reciente. Verificar que todos los servicios que utilizan OpenSSL hayan sido actualizados y reiniciados.",
                "exploit_available": False,
            },
            {
                "id": f"{scanner}-f-3",
                "name": "Default Credentials on MySQL Database",
                "severity": "high",
                "cvss": 7.2,
                "cve": "CVE-2025-1215",
                "host": "192.168.1.30",
                "port": "3306",
                "protocol": "tcp",
                "description": "La base de datos MySQL está utilizando credenciales por defecto (root/sin contraseña), lo que permite acceso administrativo no autorizado a toda la base de datos.",
                "solution": "Cambiar inmediatamente las credenciales por defecto, implementar políticas de contraseñas seguras y deshabilitar el acceso remoto a la base de datos si no es necesario.",
                "exploit_available": True,
            },
            {
                "id": f"{scanner}-f-4",
                "name": "SMBv3 Remote Code Execution",
                "severity": "high",
                "cvss": 6.5,
                "cve": "CVE-2025-1220",
                "host": "192.168.1.20",
                "port": "445",
                "protocol": "tcp",
                "description": "Vulnerabilidad de ejecución remota de código en el protocolo SMBv3 que afecta a servidores Windows. Un atacante en la red local podría ejecutar código arbitrario enviando paquetes especialmente diseñados.",
                "solution": "Aplicar el parche de seguridad de Microsoft correspondiente. Deshabilitar SMBv3 si no es necesario y segmentar la red para limitar el alcance del protocolo SMB.",
                "exploit_available": True,
            },
            {
                "id": f"{scanner}-f-5",
                "name": "Apache Tomcat Path Traversal",
                "severity": "medium",
                "cvss": 5.4,
                "cve": "CVE-2025-1189",
                "host": "192.168.1.18",
                "port": "8080",
                "protocol": "tcp",
                "description": "Se detectó una vulnerabilidad de path traversal en Apache Tomcat que permite a un atacante leer archivos fuera del directorio web root mediante secuencias de directorio codificadas.",
                "solution": "Actualizar Apache Tomcat a la versión 9.0.90 o superior. Configurar adecuadamente el SecurityManager y restringir los directorios accesibles.",
                "exploit_available": False,
            },
            {
                "id": f"{scanner}-f-6",
                "name": "Weak TLS Ciphers Configuration",
                "severity": "medium",
                "cvss": 5.0,
                "cve": "CVE-2025-1234",
                "host": "192.168.1.10",
                "port": "443",
                "protocol": "tcp",
                "description": "El servidor web está configurado con cifrados TLS débiles (TLS 1.0/1.1 y suites de cifrado RC4), lo que permite ataques de downgrade y descifrado de tráfico por parte de atacantes en la red.",
                "solution": "Deshabilitar TLS 1.0 y 1.1, habilitar solo TLS 1.2 y 1.3 con suites de cifrado fuertes. Utilizar herramientas como SSL Labs para verificar la configuración.",
                "exploit_available": False,
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
        "alerts_by_severity": {"disaster": 1, "high": 3, "average": 2, "warning": 2, "information": 0},
        "hosts_monitored": 24,
        "hosts_by_location": {"Trujillo": 8, "Lima": 6, "Genesys": 5, "Canadá": 5},
        "avg_cpu": 45.2,
        "avg_ram": 62.8,
        "avg_disk": 71.5,
        "avg_network_util": 34.7,
        "uptime_percentage": 99.87,
        "top_cpu_hosts": [
            {"host": "srv-web-01", "cpu": 92.3, "location": "Trujillo"},
            {"host": "srv-db-01", "cpu": 78.5, "location": "Lima"},
            {"host": "srv-app-02", "cpu": 67.1, "location": "Genesys"},
        ],
        "top_memory_hosts": [
            {"host": "srv-db-01", "ram": 85.4, "location": "Lima"},
            {"host": "srv-app-01", "ram": 76.2, "location": "Trujillo"},
        ],
        "recent_alerts": [
            {
                "name": "CPU high on srv-web-01",
                "severity": "high",
                "event_type": "trigger",
                "status": "PROBLEM",
                "host": "srv-web-01",
                "location": "Trujillo",
                "service": "CPU",
                "description": "CPU al 92.3% durante más de 10 minutos consecutivos, superando el umbral crítico del 90%.",
                "started_at": (datetime.utcnow() - timedelta(minutes=15)).isoformat(),
                "duration_minutes": 15,
            },
            {
                "name": "Disk space low on srv-db-01",
                "severity": "high",
                "event_type": "trigger",
                "status": "PROBLEM",
                "host": "srv-db-01",
                "location": "Lima",
                "service": "Disk",
                "description": "Disco /data al 85% de capacidad. Se recomienda expansión de almacenamiento o limpieza de logs.",
                "started_at": (datetime.utcnow() - timedelta(hours=1)).isoformat(),
                "duration_minutes": 60,
            },
            {
                "name": "Memory utilization high on srv-app-01",
                "severity": "average",
                "event_type": "trigger",
                "status": "PROBLEM",
                "host": "srv-app-01",
                "location": "Trujillo",
                "service": "Memory",
                "description": "Uso de memoria RAM al 76.2%, cerca del umbral crítico del 80%.",
                "started_at": (datetime.utcnow() - timedelta(hours=3)).isoformat(),
                "duration_minutes": 180,
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
        "alerts": {"total": 156, "critical": 3, "high": 9, "medium": 14, "low": 22, "info": 30},
        "alerts_by_category": {
            "intrusion_detection": 42,
            "malware": 18,
            "policy_violation": 35,
            "authentication_failure": 28,
            "file_integrity": 33,
        },
        "agents": {"total": 18, "active": 15, "disconnected": 2, "never_connected": 1},
        "agents_by_os": {
            "Windows": 10,
            "Linux": 6,
            "macOS": 1,
            "other": 1,
        },
        "manager_status": "healthy",
        "last_attack_detected": (datetime.utcnow() - timedelta(hours=6)).isoformat(),
        "top_events": [
            {"rule_id": 100001, "description": "Multiple SSH authentication failures from same IP", "count": 23, "severity": "high"},
            {"rule_id": 100002, "description": "File integrity change on critical system binary", "count": 5, "severity": "critical"},
            {"rule_id": 100003, "description": "Malware signature detected on endpoint", "count": 3, "severity": "critical"},
            {"rule_id": 100004, "description": "Windows registry modification detected", "count": 12, "severity": "medium"},
        ],
        "agent_name": "WAZUH-AGENT-MOCK",
        "compliance_status": {
            "pci_dss": 78.5,
            "iso_27001": 82.3,
            "nist": 75.1,
        },
    }


def _mock_uptime_kuma() -> dict:
    return {
        "configured": True,
        "active": True,
        "has_data": True,
        "last_sync": datetime.utcnow().isoformat(),
        "services": {"total": 12, "up": 10, "down": 1, "pending": 1},
        "services_detail": [
            {"name": "Portal Web Corporativo", "status": "up", "uptime_30d": 99.98, "response_time_ms": 145},
            {"name": "API Gateway", "status": "up", "uptime_30d": 99.95, "response_time_ms": 89},
            {"name": "Base de Datos Principal", "status": "up", "uptime_30d": 99.99, "response_time_ms": 12},
            {"name": "Servicio de Correo", "status": "up", "uptime_30d": 99.87, "response_time_ms": 234},
            {"name": "VPN Corporativa", "status": "up", "uptime_30d": 99.91, "response_time_ms": 56},
            {"name": "Sistema de Backup", "status": "down", "uptime_30d": 95.20, "response_time_ms": 0},
            {"name": "Active Directory", "status": "up", "uptime_30d": 100.0, "response_time_ms": 18},
            {"name": "Servicio DNS", "status": "up", "uptime_30d": 99.99, "response_time_ms": 22},
            {"name": "Balanceador de Carga", "status": "up", "uptime_30d": 100.0, "response_time_ms": 5},
            {"name": "Sistema de Monitoreo", "status": "up", "uptime_30d": 99.97, "response_time_ms": 67},
            {"name": "Firewall Perimetral", "status": "up", "uptime_30d": 100.0, "response_time_ms": 3},
            {"name": "Servicio FTP/SFTP", "status": "pending", "uptime_30d": 98.50, "response_time_ms": 0},
        ],
        "uptime_percentage": 99.12,
        "status": "degraded",
        "incidents_30d": 3,
        "total_outage_minutes_30d": 38,
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

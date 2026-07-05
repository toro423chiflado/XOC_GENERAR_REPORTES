import json
import os
import sys
import uuid

import boto3
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "_vendor"))
import requests

lambda_client = boto3.client("lambda")
CONVERTIR_DOCX_FN = os.environ.get("CONVERTIR_DOCX_FUNCTION", "")

JSON_SCHEMA = """{
  "cliente": "Nombre del cliente",
  "periodo": "Periodo del reporte",
  "fecha_reporte": "Fecha de emision",
  "herramientas": "Descripcion de herramientas usadas",
  "entorno": "Descripcion del entorno monitoreado",
  "resumen_ejecutivo": "Resumen ejecutivo completo",
  "analisis_comparativo": "Analisis comparativo de vulnerabilidades",
  "resultados_obtenidos": "Resultados obtenidos en la semana",
  "proximas_acciones": "Proximas acciones a realizar",
  "requerimiento": "Requerimiento del cliente",
  "hallazgos_web_externo": "Hallazgos de dominio web externo",
  "hallazgos_ips_publicas": "Hallazgos de IPs publicas",
  "hallazgos_fw_teletrabajo": "Hallazgos de firewall y teletrabajo",
  "hallazgos_servidores": "Hallazgos de servidores",
  "estado_switches": "Estado de switches",
  "estado_wifi": "Estado de WiFi",
  "estado_desktops": "Estado de desktops",
  "estado_ot_iot": "Estado de OT/IoT",
  "acciones_semana": "Acciones trabajadas durante la semana",
  "resultados_seguridad": "Resultados de seguridad obtenidos",
  "recomendaciones": ["Recomendacion 1", "Recomendacion 2"],
  "noticias_seguridad": ["Noticia 1", "Noticia 2"]
}"""

SYSTEM_PROMPT = """Eres un analista de seguridad que genera reportes ejecutivos.
Debes generar SOLO un objeto JSON valido, sin texto adicional, sin markdown, sin explicaciones.
El JSON debe seguir ESTRICTAMENTE este schema:

{json_schema}

Reglas:
- Usa texto profesional y conciso.
- Incluye datos concretos con numeros y metricas cuando esten disponibles.
- Las listas (recomendaciones, noticias) deben tener al menos 3 elementos cada una.
- No escapes caracteres HTML.
- No incluyas campos adicionales fuera del schema.
- Responde UNICAMENTE con el JSON, sin ningun otro texto."""


def _invoke_convertir_docx(datos_json: dict, tenant_id: str) -> dict:
    if not CONVERTIR_DOCX_FN:
        raise RuntimeError("CONVERTIR_DOCX_FUNCTION no configurada")
    resp = lambda_client.invoke(
        FunctionName=CONVERTIR_DOCX_FN,
        InvocationType="RequestResponse",
        Payload=json.dumps({"datos": datos_json, "tenant_id": tenant_id}),
    )
    return json.loads(resp["Payload"].read())


def _call_groq(prompt: str, system_prompt: str) -> str:
    api_key = os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY no configurada")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    data = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": 8192,
        "temperature": 0.3,
    }
    response = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers=headers,
        json=data,
        timeout=60,
    )

    if response.status_code != 200:
        error_detail = response.text
        raise RuntimeError(f"Groq API error {response.status_code}: {error_detail}")

    return response.json()["choices"][0]["message"]["content"]


def handler(event, context):
    try:
        if isinstance(event.get("body"), str):
            body = json.loads(event["body"])
        else:
            body = event

        contenido_reporte = body.get("contenido_reporte", "")
        indicaciones = body.get("indicaciones", "")
        tenant_id = body.get("tenant_id", "tenant-unknown")
        softwares = body.get("softwares_list", "")

        prompt = f"""{SYSTEM_PROMPT.format(json_schema=JSON_SCHEMA)}

DATOS DEL REPORTE:
------------------
{contenido_reporte}

INDICACIONES ADICIONALES:
-------------------------
{indicaciones}

Genera el JSON del reporte siguiendo estrictamente el schema especificado.
NO incluyas texto antes ni despues del JSON.
NO uses ```json ni ```.
SOLO el JSON puro."""

        json_str = _call_groq(prompt, SYSTEM_PROMPT.format(json_schema=JSON_SCHEMA))

        json_str = json_str.strip()
        if json_str.startswith("```json"):
            json_str = json_str[7:]
        if json_str.startswith("```"):
            json_str = json_str[3:]
        if json_str.endswith("```"):
            json_str = json_str[:-3]
        json_str = json_str.strip()

        datos_json = json.loads(json_str)
        datos_json["softwares_incluidos"] = softwares
        datos_json["tenant_id"] = tenant_id

        resultado_docx = _invoke_convertir_docx(datos_json, tenant_id)

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
            "body": json.dumps(
                {
                    "success": True,
                    "datos_json": datos_json,
                    "documento_docx": resultado_docx.get("body", resultado_docx),
                }
            ),
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"success": False, "error": str(e)}),
        }

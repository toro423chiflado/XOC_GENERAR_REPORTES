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
  "servicio_monitoreo": "Descripcion del servicio",
  "herramienta_1": "Herramienta 1",
  "herramienta_2": "Herramienta 2",
  "herramienta_3": "Herramienta 3",
  "herramienta_4": "Herramienta 4",
  "herramienta_5": "Herramienta 5",
  "herramienta_6": "Herramienta 6",
  "herramienta_7": "Herramienta 7",
  "datos_base": "Datos base del monitoreo",
  "entorno": "Descripcion del entorno",
  "resumen_parrafo_1": "Parrafo 1 resumen",
  "resumen_parrafo_2": "Parrafo 2 resumen",
  "resumen_parrafo_3": "Parrafo 3 resumen",
  "resumen_parrafo_4": "Parrafo 4 resumen",
  "analisis_comparativo": "Analisis comparativo completo",
  "observacion_tecnica": "Observacion tecnica",
  "comp_critico_pasada": "0",
  "comp_critico_actual": "0",
  "comp_critico_variacion": "0",
  "comp_alto_pasada": "3",
  "comp_alto_actual": "3",
  "comp_alto_variacion": "0",
  "comp_medio_pasada": "80",
  "comp_medio_actual": "81",
  "comp_medio_variacion": "1",
  "comp_bajo_pasada": "26",
  "comp_bajo_actual": "26",
  "comp_bajo_variacion": "0",
  "comp_info_pasada": "0",
  "comp_info_actual": "0",
  "comp_info_variacion": "0",
  "resultado_1": "Resultado 1",
  "resultado_2": "Resultado 2",
  "resultado_3": "Resultado 3",
  "resultado_4": "Resultado 4",
  "resultado_5": "Resultado 5",
  "resultado_6": "Resultado 6",
  "resultado_7": "Resultado 7",
  "accion_1": "Accion 1",
  "accion_2": "Accion 2",
  "accion_3": "Accion 3",
  "accion_4": "Accion 4",
  "accion_5": "Accion 5",
  "accion_6": "Accion 6",
  "requerimiento_1": "Req 1",
  "requerimiento_2": "Req 2",
  "requerimiento_3": "Req 3",
  "requerimiento_4": "Req 4",
  "requerimiento_5": "Req 5",
  "requerimiento_6": "Req 6",
  "requerimiento_7": "Req 7",
  "requerimiento_8": "Req 8",
  "hallazgo_web_1": "Hallazgo web 1",
  "hallazgo_web_2": "Hallazgo web 2",
  "hallazgo_web_3": "Hallazgo web 3",
  "hallazgo_web_4": "Hallazgo web 4",
  "hallazgo_web_5": "Hallazgo web 5",
  "hallazgo_web_6": "Hallazgo web 6",
  "hallazgo_ips_1": "Hallazgo IPs 1",
  "hallazgo_ips_2": "Hallazgo IPs 2",
  "hallazgo_ips_3": "Hallazgo IPs 3",
  "hallazgo_ips_4": "Hallazgo IPs 4",
  "hallazgo_ips_5": "Hallazgo IPs 5",
  "hallazgo_ips_6": "Hallazgo IPs 6",
  "hallazgo_ips_7": "Hallazgo IPs 7",
  "hallazgo_ips_8": "Hallazgo IPs 8",
  "hallazgo_ips_9": "Hallazgo IPs 9",
  "hallazgo_ips_10": "Hallazgo IPs 10",
  "hallazgo_ips_11": "Hallazgo IPs 11",
  "hallazgo_ips_12": "Hallazgo IPs 12",
  "hallazgo_ips_13": "Hallazgo IPs 13",
  "hallazgo_ips_14": "Hallazgo IPs 14",
  "hallazgo_fw_1": "Hallazgo FW 1",
  "hallazgo_fw_2": "Hallazgo FW 2",
  "hallazgo_fw_3": "Hallazgo FW 3",
  "hallazgo_fw_4": "Hallazgo FW 4",
  "hallazgo_fw_5": "Hallazgo FW 5",
  "hallazgo_fw_6": "Hallazgo FW 6",
  "servidor_intro": "Intro servidores",
  "servidor_resumen": "Resumen servidores",
  "servidor_genesys": "Estado IPS Genesys",
  "serv_activos_trujillo": "Activos Trujillo",
  "serv_hallazgos_trujillo": "Hallazgos Trujillo",
  "serv_riesgo_trujillo": "Riesgo Trujillo",
  "serv_activos_genesys": "Activos Genesys",
  "serv_hallazgos_genesys": "Hallazgos Genesys",
  "serv_riesgo_genesys": "Riesgo Genesys",
  "serv_activos_lima": "Activos Lima",
  "serv_hallazgos_lima": "Hallazgos Lima",
  "serv_riesgo_lima": "Riesgo Lima",
  "serv_activos_canada": "Activos Canada",
  "serv_hallazgos_canada": "Hallazgos Canada",
  "serv_riesgo_canada": "Riesgo Canada",
  "servidor_trujillo_1": "Detalle Trujillo 1",
  "servidor_trujillo_2": "Detalle Trujillo 2",
  "servidor_trujillo_3": "Detalle Trujillo 3",
  "servidor_genesys_2": "Detalle Genesys 2",
  "servidor_lima": "Detalle Lima",
  "servidor_canada_1": "Detalle Canada 1",
  "servidor_canada_2": "Detalle Canada 2",
  "prioridad_1": "Prioridad tecnica 1",
  "prioridad_2": "Prioridad tecnica 2",
  "prioridad_3": "Prioridad tecnica 3",
  "prioridad_4": "Prioridad tecnica 4",
  "servidor_estado": "Estado servidores",
  "switches_parrafo_1": "Switches parrafo 1",
  "switches_parrafo_2": "Switches parrafo 2",
  "switches_parrafo_3": "Switches parrafo 3",
  "wifi_texto": "Estado WiFi",
  "desktops_parrafo_1": "Desktops parrafo 1",
  "desktops_parrafo_2": "Desktops parrafo 2",
  "ot_iot_texto": "Estado OT/IoT",
  "accion_semana_1": "Accion semana 1",
  "accion_semana_2": "Accion semana 2",
  "accion_semana_3": "Accion semana 3",
  "accion_semana_4": "Accion semana 4",
  "accion_semana_5": "Accion semana 5",
  "accion_semana_6": "Accion semana 6",
  "accion_semana_7": "Accion semana 7",
  "accion_semana_8": "Accion semana 8",
  "accion_semana_9": "Accion semana 9",
  "accion_semana_10": "Accion semana 10",
  "accion_semana_11": "Accion semana 11",
  "accion_semana_12": "Accion semana 12",
  "accion_semana_13": "Accion semana 13",
  "accion_semana_14": "Accion semana 14",
  "accion_semana_15": "Accion semana 15",
  "resultado_seguridad_1": "Resultado seguridad",
  "recomendaciones": ["Rec 1", "Rec 2", "Rec 3"],
  "noticias_seguridad": ["Noticia 1", "Noticia 2", "Noticia 3"]
}"""

ALL_FIELDS = {
    "cliente", "periodo", "fecha_reporte", "servicio_monitoreo",
    "herramienta_1", "herramienta_2", "herramienta_3", "herramienta_4",
    "herramienta_5", "herramienta_6", "herramienta_7",
    "datos_base", "entorno",
    "resumen_parrafo_1", "resumen_parrafo_2", "resumen_parrafo_3", "resumen_parrafo_4",
    "analisis_comparativo", "observacion_tecnica",
    "comp_critico_pasada", "comp_critico_actual", "comp_critico_variacion",
    "comp_alto_pasada", "comp_alto_actual", "comp_alto_variacion",
    "comp_medio_pasada", "comp_medio_actual", "comp_medio_variacion",
    "comp_bajo_pasada", "comp_bajo_actual", "comp_bajo_variacion",
    "comp_info_pasada", "comp_info_actual", "comp_info_variacion",
    "resultado_1", "resultado_2", "resultado_3", "resultado_4", "resultado_5", "resultado_6", "resultado_7",
    "accion_1", "accion_2", "accion_3", "accion_4", "accion_5", "accion_6",
    "requerimiento_1", "requerimiento_2", "requerimiento_3", "requerimiento_4",
    "requerimiento_5", "requerimiento_6", "requerimiento_7", "requerimiento_8",
    "hallazgo_web_1", "hallazgo_web_2", "hallazgo_web_3", "hallazgo_web_4", "hallazgo_web_5", "hallazgo_web_6",
    "hallazgo_ips_1", "hallazgo_ips_2", "hallazgo_ips_3", "hallazgo_ips_4", "hallazgo_ips_5",
    "hallazgo_ips_6", "hallazgo_ips_7", "hallazgo_ips_8", "hallazgo_ips_9", "hallazgo_ips_10",
    "hallazgo_ips_11", "hallazgo_ips_12", "hallazgo_ips_13", "hallazgo_ips_14",
    "hallazgo_fw_1", "hallazgo_fw_2", "hallazgo_fw_3", "hallazgo_fw_4", "hallazgo_fw_5", "hallazgo_fw_6",
    "servidor_intro", "servidor_resumen", "servidor_genesys",
    "serv_activos_trujillo", "serv_hallazgos_trujillo", "serv_riesgo_trujillo",
    "serv_activos_genesys", "serv_hallazgos_genesys", "serv_riesgo_genesys",
    "serv_activos_lima", "serv_hallazgos_lima", "serv_riesgo_lima",
    "serv_activos_canada", "serv_hallazgos_canada", "serv_riesgo_canada",
    "servidor_trujillo_1", "servidor_trujillo_2", "servidor_trujillo_3",
    "servidor_genesys_2", "servidor_lima", "servidor_canada_1", "servidor_canada_2",
    "prioridad_1", "prioridad_2", "prioridad_3", "prioridad_4", "servidor_estado",
    "switches_parrafo_1", "switches_parrafo_2", "switches_parrafo_3",
    "wifi_texto", "desktops_parrafo_1", "desktops_parrafo_2", "ot_iot_texto",
    "accion_semana_1", "accion_semana_2", "accion_semana_3", "accion_semana_4", "accion_semana_5",
    "accion_semana_6", "accion_semana_7", "accion_semana_8", "accion_semana_9", "accion_semana_10",
    "accion_semana_11", "accion_semana_12", "accion_semana_13", "accion_semana_14", "accion_semana_15",
    "resultado_seguridad_1",
    "recomendaciones", "noticias_seguridad",
}

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

        for k, v in datos_json.items():
            if isinstance(v, list):
                datos_json[k] = "\n".join(f"- {item}" for item in v)

        datos_json["softwares_incluidos"] = softwares
        datos_json["tenant_id"] = tenant_id

        for placeholder in ALL_FIELDS:
            if placeholder not in datos_json:
                datos_json[placeholder] = f"[Pendiente]"

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

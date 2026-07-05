import json
import os
import sys
import uuid

import boto3
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "_vendor"))
import requests

lambda_client = boto3.client("lambda")
CONVERTIR_DOCX_FN = os.environ.get("CONVERTIR_DOCX_FUNCTION", "")

ALL_FIELDS = [
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
]

SYSTEM_PROMPT = """Eres un analista de seguridad senior generando un reporte ejecutivo en formato DOCX.
Debes generar SOLO un objeto JSON valido, sin markdown, sin explicaciones, sin texto adicional.

El JSON sera inyectado directamente en una plantilla DOCX profesional. Usa los DATOS DEL REPORTE provistos para generar contenido detallado, tecnico y con metricas reales.

CAMPOS REQUERIDOS (todos string a menos que se indique):

=== DATOS GENERALES ===
cliente, periodo, fecha_reporte, servicio_monitoreo,
herramienta_1..7, datos_base, entorno

=== RESUMEN EJECUTIVO ===
resumen_parrafo_1..4 (4 parrafos detallados)

=== ANALISIS COMPARATIVO ===
analisis_comparativo (texto analizando tabla de vulnerabilidades),
observacion_tecnica

=== TABLA COMPARATIVA (valores numericos enteros) ===
comp_critico_{pasada,actual,variacion},
comp_alto_{pasada,actual,variacion},
comp_medio_{pasada,actual,variacion},
comp_bajo_{pasada,actual,variacion},
comp_info_{pasada,actual,variacion}

=== RESULTADOS (7) Y ACCIONES (6) ===
resultado_1..7, accion_1..6, requerimiento_1..8

=== HALLAZGOS POR DOMINIO ===
hallazgo_web_1..6, hallazgo_ips_1..14, hallazgo_fw_1..6

=== SERVIDORES ===
servidor_intro, servidor_resumen, servidor_genesys,
serv_activos_{trujillo,genesys,lima,canada},
serv_hallazgos_{trujillo,genesys,lima,canada},
serv_riesgo_{trujillo,genesys,lima,canada},
servidor_trujillo_1..3, servidor_genesys_2, servidor_lima, servidor_canada_1..2,
prioridad_1..4, servidor_estado

=== INFRAESTRUCTURA ===
switches_parrafo_1..3, wifi_texto, desktops_parrafo_1..2, ot_iot_texto,
accion_semana_1..15, resultado_seguridad_1,
recomendaciones (array 3 items), noticias_seguridad (array 3 items)

REGLAS:
- Texto profesional con numeros y metricas extraidas de los DATOS DEL REPORTE
- Arrays se convierten a lista con vinetas
- Sin HTML escaping
- Sin campos adicionales
- SOLO JSON"""


def _invoke_convertir_docx(datos_json: dict, tenant_id: str) -> dict:
    if not CONVERTIR_DOCX_FN:
        raise RuntimeError("CONVERTIR_DOCX_FUNCTION no configurada")
    resp = lambda_client.invoke(
        FunctionName=CONVERTIR_DOCX_FN,
        InvocationType="RequestResponse",
        Payload=json.dumps({"datos": datos_json, "tenant_id": tenant_id}),
    )
    return json.loads(resp["Payload"].read())


def _call_gemini(prompt: str, system_prompt: str) -> str:
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY no configurada")

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    data = {
        "system_instruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.3,
            "maxOutputTokens": 8192,
        },
    }
    response = requests.post(url, headers={"Content-Type": "application/json"}, json=data, timeout=120)

    if response.status_code != 200:
        raise RuntimeError(f"Gemini API error {response.status_code}: {response.text}")

    result = response.json()
    candidates = result.get("candidates", [])
    if not candidates:
        raise RuntimeError(f"Gemini: sin candidatos en respuesta: {result}")

    return candidates[0]["content"]["parts"][0]["text"]


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

        prompt = f"""{contenido_reporte}

INDICACIONES ADICIONALES:
{indicaciones}

Genera el JSON completo del reporte."""

        json_str = _call_gemini(prompt, SYSTEM_PROMPT)

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
                datos_json[placeholder] = ""

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

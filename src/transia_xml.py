import json, os, sys
import boto3

lambda_client = boto3.client("lambda")
CONVERTIR_DOCX_FN = os.environ.get("CONVERTIR_DOCX_FUNCTION", "")

ALL_FIELDS = [
    "cliente","periodo","fecha_reporte","servicio_monitoreo",
    "herramienta_1","herramienta_2","herramienta_3","herramienta_4","herramienta_5","herramienta_6","herramienta_7",
    "datos_base","entorno",
    "resumen_parrafo_1","resumen_parrafo_2","resumen_parrafo_3","resumen_parrafo_4",
    "analisis_comparativo","observacion_tecnica",
    "comp_critico_pasada","comp_critico_actual","comp_critico_variacion",
    "comp_alto_pasada","comp_alto_actual","comp_alto_variacion",
    "comp_medio_pasada","comp_medio_actual","comp_medio_variacion",
    "comp_bajo_pasada","comp_bajo_actual","comp_bajo_variacion",
    "comp_info_pasada","comp_info_actual","comp_info_variacion",
    "resultado_1","resultado_2","resultado_3","resultado_4","resultado_5","resultado_6","resultado_7",
    "accion_1","accion_2","accion_3","accion_4","accion_5","accion_6",
    "requerimiento_1","requerimiento_2","requerimiento_3","requerimiento_4",
    "requerimiento_5","requerimiento_6","requerimiento_7","requerimiento_8",
    "hallazgo_web_1","hallazgo_web_2","hallazgo_web_3","hallazgo_web_4","hallazgo_web_5","hallazgo_web_6",
    "hallazgo_ips_1","hallazgo_ips_2","hallazgo_ips_3","hallazgo_ips_4","hallazgo_ips_5",
    "hallazgo_ips_6","hallazgo_ips_7","hallazgo_ips_8","hallazgo_ips_9","hallazgo_ips_10",
    "hallazgo_ips_11","hallazgo_ips_12","hallazgo_ips_13","hallazgo_ips_14",
    "hallazgo_fw_1","hallazgo_fw_2","hallazgo_fw_3","hallazgo_fw_4","hallazgo_fw_5","hallazgo_fw_6",
    "servidor_intro","servidor_resumen","servidor_genesys",
    "serv_activos_trujillo","serv_hallazgos_trujillo","serv_riesgo_trujillo",
    "serv_activos_genesys","serv_hallazgos_genesys","serv_riesgo_genesys",
    "serv_activos_lima","serv_hallazgos_lima","serv_riesgo_lima",
    "serv_activos_canada","serv_hallazgos_canada","serv_riesgo_canada",
    "servidor_trujillo_1","servidor_trujillo_2","servidor_trujillo_3",
    "servidor_genesys_2","servidor_lima","servidor_canada_1","servidor_canada_2",
    "prioridad_1","prioridad_2","prioridad_3","prioridad_4","servidor_estado",
    "switches_parrafo_1","switches_parrafo_2","switches_parrafo_3",
    "wifi_texto","desktops_parrafo_1","desktops_parrafo_2","ot_iot_texto",
    "accion_semana_1","accion_semana_2","accion_semana_3","accion_semana_4","accion_semana_5",
    "accion_semana_6","accion_semana_7","accion_semana_8","accion_semana_9","accion_semana_10",
    "accion_semana_11","accion_semana_12","accion_semana_13","accion_semana_14","accion_semana_15",
    "resultado_seguridad_1","recomendaciones","noticias_seguridad","conclusiones",
]

SYSTEM_PROMPT = """Eres un analista senior de ciberseguridad redactando un reporte ejecutivo profesional para un cliente corporativo. El reporte debe transmitir seriedad, experiencia y valor analitico.

DIRECTRICES DE CALIDAD PROFESIONAL:
- Lenguaje ejecutivo formal, como para un CEO o CISO
- Datos especificos con numeros y metricas concretas (nunca terminos vagos como "varios" o "algunos")
- Vocabulario tecnico apropiado pero comprensible para la alta direccion
- Parrafos completos con estructura clara (minimo 2-3 oraciones por campo)
- Tono objetivo, analitico y orientado a soluciones
- Cada hallazgo debe incluir impacto y recomendacion

CAMPOS (131 total):
cliente, periodo, fecha_reporte, servicio_monitoreo,
herramienta_1..7, datos_base, entorno,
resumen_parrafo_1..4, analisis_comparativo, observacion_tecnica,
comp_critico|alto|medio|bajo|info_{pasada,actual,variacion},
resultado_1..7, accion_1..6, requerimiento_1..8,
hallazgo_web_1..6, hallazgo_ips_1..14, hallazgo_fw_1..6,
servidor_intro|resumen|genesys,
serv_activos|hallazgos|riesgo_{trujillo,genesys,lima,canada},
servidor_trujillo_1..3|genesys_2|lima|canada_1..2,
prioridad_1..4, servidor_estado,
switches_parrafo_1..3, wifi_texto, desktops_parrafo_1..2, ot_iot_texto,
accion_semana_1..15, resultado_seguridad_1, conclusiones,
recomendaciones (array 3), noticias_seguridad (array 3)

REGLA FUNDAMENTAL: Responde UNICAMENTE con el objeto JSON. Ningun texto adicional. Ningun campo vacio."""


def _parse_json(text):
    if not text or not text.strip():
        raise ValueError("_parse_json: entrada vacia")
    text = text.strip()
    for prefix in ("```json", "```"):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()
    if not text:
        raise ValueError("_parse_json: texto vacio tras limpiar markdown")
    return json.loads(text)


def _call_bedrock_all(base_prompt):
    model_id = os.environ.get("BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20240620-v1:0")
    compact_fields = """cliente, periodo, fecha_reporte, servicio_monitoreo,
herramienta_1..7, datos_base, entorno,
resumen_parrafo_1..4, analisis_comparativo, observacion_tecnica,
comp_critico|alto|medio|bajo|info_{pasada,actual,variacion},
resultado_1..7, accion_1..6, requerimiento_1..8,
hallazgo_web_1..6, hallazgo_ips_1..14, hallazgo_fw_1..6,
servidor_intro|resumen|genesys,
serv_activos|hallazgos|riesgo_{trujillo,genesys,lima,canada},
servidor_trujillo_1..3|genesys_2|lima|canada_1..2,
prioridad_1..4, servidor_estado,
switches_parrafo_1..3, wifi_texto, desktops_parrafo_1..2, ot_iot_texto,
accion_semana_1..15, resultado_seguridad_1, conclusiones,
recomendaciones (array 3), noticias_seguridad (array 3)"""
    prompt = f"""{base_prompt}

Genera un objeto JSON valido con los siguientes campos (objeto, NO array).
Cada campo debe contener texto profesional, detallado y con datos especificos.

Campos a incluir:
{compact_fields}

REGLAS:
- Sustituye ".." por numeros consecutivos (ej. herramienta_1 a herramienta_7)
- comp_* = numeros enteros (sin comillas)
- arrays = exactamente 3 strings descriptivos cada uno
- Capitalizacion correcta en nombres propios y titulos
- Parrafos completos de 2-3 oraciones como minimo
- NUNCA campos vacios
- SOLO el JSON, sin texto antes ni despues"""
    client = boto3.client("bedrock-runtime")
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 4096,
        "temperature": 0.3,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": prompt}],
    })
    try:
        resp = client.invoke_model(
            modelId=model_id,
            contentType="application/json",
            accept="application/json",
            body=body,
        )
        result = json.loads(resp["body"].read())
        text = result["content"][0]["text"]
        if not text:
            raise RuntimeError("Bedrock devolvio contenido vacio")
    except Exception as e:
        raise RuntimeError(f"Bedrock ({model_id}): {e}")

    try:
        datos = _parse_json(text)
    except (ValueError, json.JSONDecodeError):
        text = text.strip()
        brace_start = text.find('{')
        if brace_start > 0:
            text = text[brace_start:]
        last_brace = text.rfind('}')
        if last_brace > 0:
            text = text[:last_brace+1]
        datos = _parse_json(text)
    return datos, model_id


def handler(event, context):
    try:
        body = json.loads(event["body"]) if isinstance(event.get("body"), str) else event
        contenido_reporte = body.get("contenido_reporte", "")
        indicaciones = body.get("indicaciones", "")
        tenant_id = body.get("tenant_id", "tenant-unknown")
        softwares = body.get("softwares_list", "")

        base_prompt = f"{contenido_reporte}\n\nINDICACIONES DEL CLIENTE: {indicaciones}"

        datos, provider = _call_bedrock_all(base_prompt)

        for k, v in datos.items():
            if isinstance(v, list):
                datos[k] = "\n".join(f"- {item}" for item in v)

        datos["softwares_incluidos"] = softwares
        datos["tenant_id"] = tenant_id
        datos["cliente"] = tenant_id
        if not datos.get("fecha_reporte"):
            from datetime import date
            meses = ["enero","febrero","marzo","abril","mayo","junio","julio","agosto","septiembre","octubre","noviembre","diciembre"]
            hoy = date.today()
            datos["fecha_reporte"] = f"{hoy.day} de {meses[hoy.month-1]} de {hoy.year}"

        for placeholder in ALL_FIELDS:
            datos.setdefault(placeholder, "")

        resultado = lambda_client.invoke(
            FunctionName=CONVERTIR_DOCX_FN,
            InvocationType="RequestResponse",
            Payload=json.dumps({"datos": datos, "tenant_id": tenant_id}),
        )
        docx_resp = json.loads(resultado["Payload"].read())

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
            "body": json.dumps({
                "success": True,
                "ai_provider": provider,
                "documento_docx": docx_resp.get("body", docx_resp),
            }),
        }
    except Exception as e:
        import traceback
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"success": False, "error": str(e), "traceback": traceback.format_exc()}),
        }

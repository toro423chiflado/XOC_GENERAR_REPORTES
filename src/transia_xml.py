import json, os, sys, time
import boto3
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "_vendor"))
import requests

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
    "resultado_seguridad_1","recomendaciones","noticias_seguridad",
]

LONG_FIELDS = [
    "resumen_parrafo_1","resumen_parrafo_2","resumen_parrafo_3","resumen_parrafo_4",
    "analisis_comparativo","observacion_tecnica",
    "hallazgo_web_1","hallazgo_web_2","hallazgo_web_3","hallazgo_web_4","hallazgo_web_5","hallazgo_web_6",
    "hallazgo_fw_1","hallazgo_fw_2","hallazgo_fw_3","hallazgo_fw_4","hallazgo_fw_5","hallazgo_fw_6",
    "servidor_intro","servidor_resumen","servidor_genesys",
    "servidor_trujillo_1","servidor_trujillo_2","servidor_trujillo_3",
    "servidor_genesys_2","servidor_lima","servidor_canada_1","servidor_canada_2",
    "switches_parrafo_1","switches_parrafo_2","switches_parrafo_3",
    "wifi_texto","desktops_parrafo_1","desktops_parrafo_2","ot_iot_texto",
    "recomendaciones","noticias_seguridad",
]

SHORT_FIELDS = [f for f in ALL_FIELDS if f not in LONG_FIELDS and f not in ("recomendaciones","noticias_seguridad")]

SYSTEM_PROMPT_SHORT = "Eres analista de seguridad. Genera SOLO JSON valido con campos cortos (texto conciso, numeros)."
SYSTEM_PROMPT_LONG = "Eres analista de seguridad senior. Genera SOLO JSON valido con parrafos descriptivos detallados usando datos del reporte."


def _parse_json(text):
    text = text.strip()
    for prefix in ("```json", "```"):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    if text.endswith("```"):
        text = text[:-3]
    return json.loads(text.strip())


def _call_groq(prompt, system_prompt, max_tokens=2500):
    api_key = os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        return None
    resp = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={
            "model": "llama-3.1-8b-instant",
            "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": 0.3,
        },
        timeout=120,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Groq API error {resp.status_code}: {resp.text}")
    return resp.json()["choices"][0]["message"]["content"]


def _call_gemini(prompt, system_prompt):
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        return None
    resp = requests.post(
        "https://generativelanguage.googleapis.com/v1/models/gemini-1.5-flash:generateContent",
        params={"key": api_key},
        headers={"Content-Type": "application/json"},
        json={
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.3, "maxOutputTokens": 8192},
        },
        timeout=120,
    )
    if resp.status_code != 200:
        detail = resp.text
        # v1 fallback to v1beta if model not found
        if "not found" in detail:
            resp = requests.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-001:generateContent?key={api_key}",
                headers={"Content-Type": "application/json"},
                json={
                    "system_instruction": {"parts": [{"text": system_prompt}]},
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"temperature": 0.3, "maxOutputTokens": 8192},
                },
                timeout=120,
            )
        if resp.status_code != 200:
            raise RuntimeError(f"Gemini API error {resp.status_code}: {resp.text}")
    candidates = resp.json().get("candidates", [])
    if not candidates:
        raise RuntimeError("Gemini: sin candidatos")
    return candidates[0]["content"]["parts"][0]["text"]


def _call_ai(prompt, system_prompt, max_tokens=2500):
    try:
        result = _call_gemini(prompt, system_prompt)
        if result is not None:
            return result, "gemini"
    except Exception as e:
        print(f"Gemini failed: {e}, falling back to Groq")

    result = _call_groq(prompt, system_prompt, max_tokens)
    if result is not None:
        return result, "groq"
    raise RuntimeError("No AI provider configured - set GEMINI_API_KEY or GROQ_API_KEY")


def handler(event, context):
    try:
        body = json.loads(event["body"]) if isinstance(event.get("body"), str) else event
        contenido_reporte = body.get("contenido_reporte", "")
        indicaciones = body.get("indicaciones", "")
        tenant_id = body.get("tenant_id", "tenant-unknown")
        softwares = body.get("softwares_list", "")

        base_prompt = f"{contenido_reporte}\n\nINDICACIONES: {indicaciones}"

        # Short fields: compact
        result_shorts, provider = _call_ai(
            f"{base_prompt}\n\nGenera JSON con estos campos EXACTAMENTE (texto conciso, numeros):\n{', '.join(SHORT_FIELDS)}\n\nrecomendaciones y noticias_seguridad como arrays de 3 strings. SOLO JSON.",
            SYSTEM_PROMPT_SHORT,
            max_tokens=1500,
        )
        datos = _parse_json(result_shorts)

        # Long fields: detailed
        time.sleep(1)
        result_longs, _ = _call_ai(
            f"{base_prompt}\n\nGenera JSON con estos campos (texto DETALLADO, parrafos completos con metricas):\n{', '.join(LONG_FIELDS)}\n\nrecomendaciones y noticias_seguridad como arrays de 3 strings. SOLO JSON.",
            SYSTEM_PROMPT_LONG,
            max_tokens=3500,
        )
        datos_long = _parse_json(result_longs)
        datos.update(datos_long)

        for k, v in datos.items():
            if isinstance(v, list):
                datos[k] = "\n".join(f"- {item}" for item in v)

        datos["softwares_incluidos"] = softwares
        datos["tenant_id"] = tenant_id

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
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"success": False, "error": str(e)}),
        }

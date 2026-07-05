import json, os
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

SYSTEM_PROMPT = """Eres un analista senior de ciberseguridad con 15 años de experiencia redactando reportes ejecutivos para clientes corporativos de alto nivel. Tu estilo de redacción es impecable, profesional y persuasivo.

NORMAS DE REDACCIÓN:
- Ortografía y gramática perfectas. Usa tildes correctamente (sí, í, ó, ú, á, é).
- Lenguaje formal y técnicamente preciso, pero comprensible para un CEO o CISO.
- Cada campo debe contener un párrafo completo de 2 a 4 oraciones bien estructuradas.
- Vocabulario rico y variado. Evita repeticiones.
- Datos concretos con cifras y métricas específicas extraídas del contenido del reporte.
- Tono objetivo, analítico y orientado a soluciones.
- Los títulos y nombres propios deben tener mayúsculas correctas.
- Sin jerga informal, muletillas ni frases hechas.

ESTRUCTURA DE LOS 131 CAMPOS:

cliente, periodo, fecha_reporte, servicio_monitoreo -> Metadatos e introducción
herramienta_1..7 -> Nombres de herramientas de seguridad desplegadas
datos_base, entorno -> Descripción del alcance y entorno evaluado
resumen_parrafo_1..4 -> Resumen ejecutivo en 4 párrafos impactantes
analisis_comparativo, observacion_tecnica -> Análisis de tendencias y observaciones técnicas
comp_critico|alto|medio|bajo|info_{pasada,actual,variacion} -> Métricas numéricas de comparativa (solo números enteros)
resultado_1..7 -> Resultados detallados por cada herramienta
accion_1..6 -> Acciones correctivas inmediatas
requerimiento_1..8 -> Requerimientos técnicos para remediación
hallazgo_web_1..6 -> Hallazgos de aplicaciones web
hallazgo_ips_1..14 -> Hallazgos por IP detectados
hallazgo_fw_1..6 -> Hallazgos de firewall
servidor_intro|resumen|genesys -> Introducción y resumen de servidores
serv_activos|hallazgos|riesgo_{trujillo,genesys,lima,canada} -> Estado por sede
servidor_trujillo_1..3|genesys_2|lima|canada_1..2 -> Detalle de servidores por ubicación
prioridad_1..4 -> Prioridades de atención
servidor_estado -> Estado general de servidores
switches_parrafo_1..3 -> Estado de switches y red
wifi_texto -> Estado de red WiFi
desktops_parrafo_1..2 -> Estado de estaciones de trabajo
ot_iot_texto -> Estado de dispositivos OT/IoT
accion_semana_1..15 -> Plan de acción semanal detallado (15 semanas)
resultado_seguridad_1 -> Resultado global de seguridad
recomendaciones -> Array de 3 recomendaciones estratégicas
noticias_seguridad -> Array de 3 noticias relevantes
conclusiones -> Conclusiones finales del reporte

REGLA ABSOLUTA: Responde ÚNICAMENTE con el objeto JSON. Sin texto adicional, sin markdown, sin explicaciones. Ningún campo vacío."""


def _parse_json(text):
    if not text or not text.strip():
        raise ValueError("_parse_json: entrada vacía")
    text = text.strip()
    for prefix in ("```json", "```"):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()
    if not text:
        raise ValueError("_parse_json: texto vacío tras limpiar markdown")
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

Con base en la información proporcionada arriba, genera un objeto JSON válido con los siguientes campos. Cada campo debe contener un párrafo profesional, detallado y con métricas concretas extraídas de los datos del reporte.

CAMPOS A INCLUIR:
{compact_fields}

INSTRUCCIONES ESPECÍFICAS:

1. Sustituye ".." por números consecutivos. Ejemplo: herramienta_1, herramienta_2, ..., herramienta_7.

2. Los campos comp_* (comparativa) deben ser SOLO números enteros, sin comillas. Ejemplo: "comp_critico_pasada": 8.

3. Los campos hallazgo_*, resultado_*, accion_*, requerimiento_* deben ser párrafos completos con:
   - Descripción del hallazgo o resultado
   - Impacto en la seguridad del negocio
   - Recomendación específica de remediación

4. Los campos de servidores (servidor_*, serv_*) deben incluir:
   - Nombre o ubicación del servidor/sede
   - Estado actual y métricas relevantes
   - Hallazgos específicos identificados

5. Los campos accion_semana_1..15 deben formar un plan de acción cronológico de 15 semanas.

6. Los arrays (recomendaciones, noticias_seguridad) deben contener EXACTAMENTE 3 strings cada uno.

7. Los campos switches_*, wifi_texto, desktops_*, ot_iot_texto deben describir el estado de la infraestructura de red, estaciones de trabajo y dispositivos OT/IoT.

8. Los campos cliente y fecha_reporte deben respetar los valores ya definidos.

9. Los campos resumen_parrafo_1..4 deben formar un resumen ejecutivo coherente y persuasivo.

10. conclusiones debe ser un párrafo final que sintetice los hallazgos más críticos y la postura de seguridad general.

CALIDAD OBLIGATORIA:
- Ortografía y gramática perfectas (con tildes)
- Párrafos de 2 a 4 oraciones bien redactados
- Datos numéricos específicos de los DATOS DEL REPORTE
- Tono ejecutivo profesional
- Sin campos vacíos
- SOLO el objeto JSON, nada más"""
    client = boto3.client("bedrock-runtime")
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 8192,
        "temperature": 0.2,
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
            raise RuntimeError("Bedrock devolvió contenido vacío")
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

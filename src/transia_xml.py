import json
import os
import uuid

import boto3
import requests

lambda_client = boto3.client("lambda")
CONVERTIR_DOCX_FN = os.environ.get("CONVERTIR_DOCX_FUNCTION", "")

XML_REPORT_SCHEMA = """<?xml version="1.0" encoding="UTF-8"?>
<reporte>
  <metadata>
    <titulo>STRING</titulo>
    <fecha_generacion>ISO8601</fecha_generacion>
    <tenant_id>STRING</tenant_id>
    <softwares_incluidos>LISTA_COMA</softwares_incluidos>
  </metadata>
  <resumen_ejecutivo>STRING</resumen_ejecutivo>
  <secciones>
    <seccion>
      <nombre>NOMBRE_SOFTWARE</nombre>
      <tipo>vulnerabilidad|monitoreo|siem|disponibilidad</tipo>
      <contenido>
        <parrafo>...</parrafo>
        <tabla>
          <encabezados><encabezado>...</encabezado></encabezados>
          <filas>
            <fila><celda>...</celda></fila>
          </filas>
        </tabla>
      </contenido>
    </seccion>
  </secciones>
  <conclusiones>STRING</conclusiones>
  <recomendaciones>
    <recomendacion>...</recomendacion>
  </recomendaciones>
</reporte>"""

SYSTEM_PROMPT = """Eres un generador de reportes de seguridad en formato XML.
Debes generar SOLO XML valido, sin texto adicional, sin markdown, sin explicaciones.
El XML debe seguir ESTRICTAMENTE este schema:

{schema}

Reglas:
- Usa tablas dentro de <contenido> cuando haya datos numericos (vulnerabilidades, hosts, etc).
- Cada seccion de software debe tener parrafos descriptivos.
- Incluye datos concretos, no textos genericos.
- Las recomendaciones deben ser accionables y especificas.
- No agregues CDATA, solo texto plano en los nodos.
- No escapes HTML, solo texto plano.
- Responde UNICAMENTE con el XML, sin ningun otro texto."""


def _invoke_convertir_docx(xml_content: str, tenant_id: str, indicaciones: str) -> dict:
    if not CONVERTIR_DOCX_FN:
        raise RuntimeError("CONVERTIR_DOCX_FUNCTION no configurada")
    resp = lambda_client.invoke(
        FunctionName=CONVERTIR_DOCX_FN,
        InvocationType="RequestResponse",
        Payload=json.dumps({"xml": xml_content, "tenant_id": tenant_id, "indicaciones": indicaciones}),
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
        "max_tokens": 4096,
        "temperature": 0.3,
    }
    response = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers=headers,
        json=data,
        timeout=30,
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

        prompt = f"""{SYSTEM_PROMPT.format(schema=XML_REPORT_SCHEMA)}

DATOS DEL REPORTE:
------------------
{contenido_reporte}

INDICACIONES ADICIONALES:
-------------------------
{indicaciones}

Genera el XML del reporte siguiendo estrictamente el schema especificado.
NO incluyas texto antes ni despues del XML.
NO uses ```xml ni ```.
SOLO el XML puro."""

        xml_generado = _call_groq(prompt, SYSTEM_PROMPT.format(schema=XML_REPORT_SCHEMA))

        xml_generado = xml_generado.strip()
        if xml_generado.startswith("```xml"):
            xml_generado = xml_generado[6:]
        if xml_generado.startswith("```"):
            xml_generado = xml_generado[3:]
        if xml_generado.endswith("```"):
            xml_generado = xml_generado[:-3]
        xml_generado = xml_generado.strip()

        if not xml_generado.startswith("<?xml"):
            xml_generado = '<?xml version="1.0" encoding="UTF-8"?>\n' + xml_generado

        resultado_docx = _invoke_convertir_docx(xml_generado, tenant_id, indicaciones)

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
            "body": json.dumps(
                {
                    "success": True,
                    "xml_generado": xml_generado,
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

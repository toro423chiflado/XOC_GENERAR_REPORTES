import json
import os
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime
from uuid import uuid4

import boto3
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "_vendor"))

try:
    from docx import Document
    from docx.shared import Inches, Pt, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.table import WD_TABLE_ALIGNMENT
except ImportError:
    Document = None

s3 = boto3.client("s3")
BUCKET = os.environ.get("BUCKET_REPORTES", "xoc-reportes-reportes-generales-dev")


def _xml_to_docx(xml_str: str, output_path: str):
    doc = Document()

    style = doc.styles["Normal"]
    font = style.font
    font.name = "Calibri"
    font.size = Pt(11)

    root = ET.fromstring(xml_str)

    metadata = root.find("metadata")
    if metadata is not None:
        titulo = metadata.findtext("titulo", "Reporte XOC")
        p = doc.add_heading(titulo, level=0)
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        doc.add_paragraph("")

        tenant = metadata.findtext("tenant_id", "")
        fecha = metadata.findtext("fecha_generacion", "")
        sw = metadata.findtext("softwares_incluidos", "")

        meta_table = doc.add_table(rows=3, cols=2)
        meta_table.style = "Light Shading Accent 1"
        meta_table.alignment = WD_TABLE_ALIGNMENT.LEFT
        meta_table.cell(0, 0).text = "Tenant ID"
        meta_table.cell(0, 1).text = tenant
        meta_table.cell(1, 0).text = "Fecha de generacion"
        meta_table.cell(1, 1).text = fecha
        meta_table.cell(2, 0).text = "Softwares incluidos"
        meta_table.cell(2, 1).text = sw
        doc.add_paragraph("")

    resumen = root.find("resumen_ejecutivo")
    if resumen is not None and resumen.text:
        doc.add_heading("Resumen Ejecutivo", level=1)
        doc.add_paragraph(resumen.text.strip())

    secciones = root.find("secciones")
    if secciones is not None:
        doc.add_heading("Detalle por Software", level=1)
        for seccion in secciones.findall("seccion"):
            nombre = seccion.findtext("nombre", "Seccion")
            tipo = seccion.findtext("tipo", "")
            doc.add_heading(f"{nombre} ({tipo})", level=2)
            contenido = seccion.find("contenido")
            if contenido is not None:
                for elem in contenido:
                    if elem.tag == "parrafo" and elem.text:
                        doc.add_paragraph(elem.text.strip())
                    elif elem.tag == "tabla":
                        encabezados = elem.find("encabezados")
                        filas = elem.find("filas")
                        if encabezados is not None:
                            headers = [h.text or "" for h in encabezados.findall("encabezado")]
                            rows_data = []
                            if filas is not None:
                                for fila in filas.findall("fila"):
                                    rows_data.append([c.text or "" for c in fila.findall("celda")])
                            if headers:
                                t = doc.add_table(rows=1 + len(rows_data), cols=len(headers))
                                t.style = "Light Shading Accent 1"
                                t.alignment = WD_TABLE_ALIGNMENT.CENTER
                                for i, h in enumerate(headers):
                                    cell = t.rows[0].cells[i]
                                    cell.text = h
                                    for paragraph in cell.paragraphs:
                                        for run in paragraph.runs:
                                            run.bold = True
                                for ri, row in enumerate(rows_data):
                                    for ci, val in enumerate(row):
                                        t.rows[ri + 1].cells[ci].text = val
                                doc.add_paragraph("")

    conclusiones = root.find("conclusiones")
    if conclusiones is not None and conclusiones.text:
        doc.add_heading("Conclusiones", level=1)
        doc.add_paragraph(conclusiones.text.strip())

    recomendaciones = root.find("recomendaciones")
    if recomendaciones is not None:
        doc.add_heading("Recomendaciones", level=1)
        for rec in recomendaciones.findall("recomendacion"):
            if rec.text:
                doc.add_paragraph(rec.text.strip(), style="List Bullet")

    doc.save(output_path)


def handler(event, context):
    try:
        if isinstance(event.get("body"), str):
            body = json.loads(event["body"])
        else:
            body = event

        xml_content = body.get("xml", "")
        tenant_id = body.get("tenant_id", "tenant-unknown")

        if not xml_content:
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
                "body": json.dumps({"success": False, "error": "Campo 'xml' requerido"}),
            }

        if Document is None:
            return {
                "statusCode": 500,
                "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
                "body": json.dumps({"success": False, "error": "python-docx no disponible - verificar capa"}),
            }

        docx_id = str(uuid4())
        s3_key = f"{tenant_id}/{docx_id}/reporte.docx"

        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            _xml_to_docx(xml_content, tmp_path)

            s3.upload_file(
                Filename=tmp_path,
                Bucket=BUCKET,
                Key=s3_key,
                ExtraArgs={"ContentType": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
            )

            url = f"s3://{BUCKET}/{s3_key}"

            return {
                "statusCode": 200,
                "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
                "body": json.dumps(
                    {
                        "success": True,
                        "documento_url": url,
                        "bucket": BUCKET,
                        "key": s3_key,
                        "tenant_id": tenant_id,
                        "formato": "docx",
                    }
                ),
            }
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    except ET.ParseError as e:
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"success": False, "error": f"Error parseando XML: {str(e)}"}),
        }
    except Exception as e:
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"success": False, "error": str(e)}),
        }

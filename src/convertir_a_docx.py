import json
import os
import sys
import tempfile
from uuid import uuid4

import boto3
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "_vendor"))

try:
    from docxtpl import DocxTemplate
except ImportError:
    DocxTemplate = None

s3 = boto3.client("s3")
BUCKET = os.environ.get("BUCKET_REPORTES", "reportes-generales-dev")
TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "..", "templates", "plantilla_reporte.docx")


def handler(event, context):
    try:
        if isinstance(event.get("body"), str):
            body = json.loads(event["body"])
        else:
            body = event

        datos = body.get("datos", {})
        tenant_id = body.get("tenant_id", "tenant-unknown")

        if not datos:
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
                "body": json.dumps({"success": False, "error": "Campo 'datos' requerido"}),
            }

        if DocxTemplate is None:
            return {
                "statusCode": 500,
                "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
                "body": json.dumps({"success": False, "error": "docxtpl no disponible - verificar _vendor"}),
            }

        if not os.path.exists(TEMPLATE_PATH):
            return {
                "statusCode": 500,
                "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
                "body": json.dumps({"success": False, "error": f"Template no encontrado: {TEMPLATE_PATH}"}),
            }

        docx_id = str(uuid4())
        s3_key = f"{tenant_id}/{docx_id}/reporte.docx"

        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            doc = DocxTemplate(TEMPLATE_PATH)
            doc.render(datos)
            doc.save(tmp_path)

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

    except Exception as e:
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"success": False, "error": str(e)}),
        }

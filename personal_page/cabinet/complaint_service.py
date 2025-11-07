# cabinet/complaint_service.py
import logging, re, xml.etree.ElementTree as ET
from html import unescape as html_unescape
from xml.sax.saxutils import escape as xml_escape
import requests
from django.conf import settings

logger = logging.getLogger('cabinet.auth')

SOAP11_GET_MEDICAL = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetMedicalClaimInformations xmlns="http://tempuri.org/">
      <userName>{user}</userName>
      <password>{password}</password>
      <pinCode>{pin}</pinCode>
    </GetMedicalClaimInformations>
  </soap:Body>
</soap:Envelope>
'''

def _post_soap(url: str, payload: str, action: str, timeout: int, verify_ssl: bool) -> requests.Response:
    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": f"\"http://tempuri.org/{action}\"",
    }
    return requests.post(url, data=payload.encode('utf-8'), headers=headers, timeout=timeout, verify=verify_ssl)

def _extract_inner_string(tag: str, body: str) -> str | None:
    m = re.search(fr'<{tag}[^>]*>(.*?)</{tag}>', body, flags=re.S | re.I)
    if m:
        return html_unescape((m.group(1) or '').strip()) or None
    m2 = re.search(r'<string\b[^>]*>(.*?)</string>', body, flags=re.S | re.I)
    return html_unescape((m2.group(1) or '').strip()) if m2 else None

def get_medical_claim_informations(pin_code: str) -> dict:
    """
    Возвращает {"ok": True, "complaints": [ {PIN_CODE, CLINIC_NAME, EVENT_OCCURRENCE_DATE}, ... ]}
    либо {"ok": False, "error": "..."}.
    """
    cfg = settings.EXTERNAL_AUTH
    url = cfg['URL']
    timeout = cfg.get('TIMEOUT', 15)
    verify_ssl = cfg.get('VERIFY_SSL', True)

    payload = SOAP11_GET_MEDICAL.format(
        user=xml_escape(cfg['USERNAME']),
        password=xml_escape(cfg['PASSWORD']),
        pin=xml_escape((pin_code or '').strip())
    )

    try:
        r = _post_soap(url, payload, action="GetMedicalClaimInformations", timeout=timeout, verify_ssl=verify_ssl)
    except requests.RequestException as e:
        logger.exception("HTTP error during GetMedicalClaimInformations")
        return {"ok": False, "error": f"http_error: {e}"}

    if r.status_code != 200:
        logger.error("GetMedicalClaimInformations non-200: %s", r.status_code)
        return {"ok": False, "error": f"http_status_{r.status_code}"}

    inner = _extract_inner_string("GetMedicalClaimInformationsResult", r.text)
    if not inner:
        return {"ok": False, "error": "empty_or_invalid_inner"}

    try:
        x = ET.fromstring(inner)
    except ET.ParseError:
        return {"ok": False, "error": "invalid_inner_xml"}

    items = []
    # из старого проекта узел назывался CLM_NOTICE_DISPETCHER
    for node in x.findall('.//CLM_NOTICE_DISPETCHER'):
        item = {
            child.tag: (child.text or '').strip()
            for child in list(node)
        }
        if item:
            # оставим только нужные ключи, если есть
            compact = {
                "PIN_CODE": item.get("PIN_CODE", ""),
                "CLINIC_NAME": item.get("CLINIC_NAME", ""),
                "EVENT_OCCURRENCE_DATE": item.get("EVENT_OCCURRENCE_DATE", ""),
            }
            items.append(compact)

    # fallback: одиночная запись
    if not items:
        node = x.find('.//CLM_NOTICE_DISPETCHER')
        if node is not None:
            item = {
                child.tag: (child.text or '').strip()
                for child in list(node)
            }
            items = [{
                "PIN_CODE": item.get("PIN_CODE", ""),
                "CLINIC_NAME": item.get("CLINIC_NAME", ""),
                "EVENT_OCCURRENCE_DATE": item.get("EVENT_OCCURRENCE_DATE", ""),
            }]

    return {"ok": True, "complaints": items}

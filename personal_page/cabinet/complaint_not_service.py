
import logging, re, xml.etree.ElementTree as ET
from html import unescape as html_unescape
from xml.sax.saxutils import escape as xml_escape
import requests
from django.conf import settings

logger = logging.getLogger('cabinet.auth')

SOAP11_GET_NON_MEDICAL = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetNonMedicalClaimInformations xmlns="http://tempuri.org/">
      <userName>{user}</userName>
      <password>{password}</password>
      <pinCode>{pin}</pinCode>
    </GetNonMedicalClaimInformations>
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
    if m2:
        return html_unescape((m2.group(1) or '').strip()) or None
    try:
        root = ET.fromstring(body)
        t = (root.text or '').strip()
        return html_unescape(t) or None
    except ET.ParseError:
        return None

def _kv(node: ET.Element) -> dict:
    return {child.tag: (child.text or '').strip() for child in list(node)}

def get_non_medical_complaints(pin_code: str) -> dict:
    """
    Возвращает {"ok": True, "complaints": [ {PIN_CODE, POLICY_NUMBER, INSURANCE_CODE, EVENT_OCCURRENCE_DATE, STATUS_NAME} ]}
    либо {"ok": False, "error": "..."}.
    """
    cfg = settings.EXTERNAL_AUTH
    payload = SOAP11_GET_NON_MEDICAL.format(
        user=xml_escape(cfg['USERNAME']),
        password=xml_escape(cfg['PASSWORD']),
        pin=xml_escape((pin_code or '').strip()),
    )
    try:
        r = _post_soap(cfg['URL'], payload, "GetNonMedicalClaimInformations",
                       cfg.get('TIMEOUT', 15), cfg.get('VERIFY_SSL', True))
    except requests.RequestException as e:
        logger.exception("HTTP error during GetNonMedicalClaimInformations")
        return {"ok": False, "error": f"http_error: {e}"}

    if r.status_code != 200:
        logger.error("GetNonMedicalClaimInformations non-200: %s", r.status_code)
        return {"ok": False, "error": f"http_status_{r.status_code}"}

    inner = _extract_inner_string("GetNonMedicalClaimInformationsResult", r.text)
    if not inner:
        return {"ok": False, "error": "empty_or_invalid_inner"}

    try:
        x = ET.fromstring(inner)
    except ET.ParseError:
        return {"ok": False, "error": "invalid_inner_xml"}

    # Возможные структуры: <DocumentElement><CLM_NOTICES>...</CLM_NOTICES>...</DocumentElement>
    items = []
    for n in x.findall('.//CLM_NOTICES'):
        items.append(_kv(n))
    if not items:
        # fallback на одиночный узел
        n = x.find('.//CLM_NOTICES')
        if n is not None:
            items = [_kv(n)]

    return {"ok": True, "complaints": items}

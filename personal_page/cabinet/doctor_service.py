# cabinet/doctor_service.py
import logging
import re
import xml.etree.ElementTree as ET
from html import unescape as html_unescape
from xml.sax.saxutils import escape as xml_escape
import requests
from django.conf import settings

logger = logging.getLogger('cabinet.auth')

# --- SOAP payloads ---

SOAP11_GET_SPECIALITIES = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetSpecialities xmlns="http://tempuri.org/">
      <userName>{user}</userName>
      <password>{password}</password>
    </GetSpecialities>
  </soap:Body>
</soap:Envelope>
'''

SOAP11_GET_DOCTORS_BY_SPECIALITY = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetDoctorsBySpecialtiy xmlns="http://tempuri.org/">
      <userName>{user}</userName>
      <password>{password}</password>
      <specialityId>{spec}</specialityId>
    </GetDoctorsBySpecialtiy>
  </soap:Body>
</soap:Envelope>
'''

SOAP11_GET_DOCTOR_CAREER = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetDoctorCareer xmlns="http://tempuri.org/">
      <userName>{user}</userName>
      <password>{password}</password>
      <doctorId>{doctor}</doctorId>
    </GetDoctorCareer>
  </soap:Body>
</soap:Envelope>
'''

# --- helpers (единственные, без дубликатов) ---

def _post_soap(url: str, payload: str, action: str, timeout: int, verify_ssl: bool) -> requests.Response:
    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": f"\"http://tempuri.org/{action}\"",
    }
    return requests.post(url, data=payload.encode('utf-8'), headers=headers, timeout=timeout, verify=verify_ssl)

def _extract_inner_string(result_tag: str, soap_xml: str) -> str | None:
    """
    Возвращает декодированный inner-XML из <{result_tag}>...</{result_tag}> или <string>...</string>.
    ВАЖНО: делаем html_unescape для &lt;...&gt;.
    """
    m = re.search(fr'<{result_tag}[^>]*>(.*?)</{result_tag}>', soap_xml, flags=re.S | re.I)
    if m:
        inner = html_unescape((m.group(1) or '').strip())
        return inner if inner else None

    m2 = re.search(r'<string\b[^>]*>(.*?)</string>', soap_xml, flags=re.S | re.I)
    if m2:
        inner = html_unescape((m2.group(1) or '').strip())
        return inner if inner else None

    try:
        root = ET.fromstring(soap_xml)
        text = html_unescape((root.text or '').strip())
        return text if text else None
    except ET.ParseError:
        return None

def _dict_from_children(node: ET.Element) -> dict:
    return {child.tag: (child.text or '').strip() for child in list(node)}

# --- API wrappers ---

def get_specialities() -> dict:
    cfg = settings.EXTERNAL_AUTH
    payload = SOAP11_GET_SPECIALITIES.format(
        user=xml_escape(cfg['USERNAME']),
        password=xml_escape(cfg['PASSWORD']),
    )
    try:
        r = _post_soap(cfg['URL'], payload, "GetSpecialities", cfg.get('TIMEOUT', 15), cfg.get('VERIFY_SSL', True))
    except requests.RequestException as e:
        logger.exception("HTTP error during GetSpecialities")
        return {"ok": False, "error": f"http_error: {e}"}

    if r.status_code != 200:
        logger.error("GetSpecialities non-200: %s", r.status_code)
        return {"ok": False, "error": f"http_status_{r.status_code}"}

    inner = _extract_inner_string("GetSpecialitiesResult", r.text)
    if not inner:
        return {"ok": False, "error": "empty_or_invalid_inner"}

    try:
        x = ET.fromstring(inner)
    except ET.ParseError:
        return {"ok": False, "error": "invalid_inner_xml"}

    items = [_dict_from_children(n) for n in x.findall('.//SPECIALITIES')]
    if not items:
        n = x.find('.//SPECIALITIES')
        if n is not None:
            items = [_dict_from_children(n)]

    return {"ok": True, "specialities": items}

def get_doctors_by_speciality(speciality_id: str) -> dict:
    cfg = settings.EXTERNAL_AUTH
    payload = SOAP11_GET_DOCTORS_BY_SPECIALITY.format(
        user=xml_escape(cfg['USERNAME']),
        password=xml_escape(cfg['PASSWORD']),
        spec=xml_escape((speciality_id or '').strip())
    )
    try:
        r = _post_soap(cfg['URL'], payload, "GetDoctorsBySpecialtiy", cfg.get('TIMEOUT', 15), cfg.get('VERIFY_SSL', True))
    except requests.RequestException as e:
        logger.exception("HTTP error during GetDoctorsBySpecialtiy")
        return {"ok": False, "error": f"http_error: {e}"}

    if r.status_code != 200:
        logger.error("GetDoctorsBySpecialtiy non-200: %s", r.status_code)
        return {"ok": False, "error": f"http_status_{r.status_code}"}

    inner = _extract_inner_string("GetDoctorsBySpecialtiyResult", r.text)
    if not inner:
        return {"ok": False, "error": "empty_or_invalid_inner"}

    try:
        x = ET.fromstring(inner)
    except ET.ParseError:
        return {"ok": False, "error": "invalid_inner_xml"}

    items = [_dict_from_children(n) for n in x.findall('.//DOCTORS')]
    if not items:
        n = x.find('.//DOCTORS')
        if n is not None:
            items = [_dict_from_children(n)]

    return {"ok": True, "doctors": items}

def get_doctor_career(doctor_id: str) -> dict:
    cfg = settings.EXTERNAL_AUTH
    payload = SOAP11_GET_DOCTOR_CAREER.format(
        user=xml_escape(cfg['USERNAME']),
        password=xml_escape(cfg['PASSWORD']),
        doctor=xml_escape((doctor_id or '').strip())
    )
    try:
        r = _post_soap(cfg['URL'], payload, "GetDoctorCareer", cfg.get('TIMEOUT', 15), cfg.get('VERIFY_SSL', True))
    except requests.RequestException as e:
        logger.exception("HTTP error during GetDoctorCareer")
        return {"ok": False, "error": f"http_error: {e}"}

    if r.status_code != 200:
        logger.error("GetDoctorCareer non-200: %s; body head: %r", r.status_code, r.text[:300])
        return {"ok": False, "error": f"http_status_{r.status_code}"}

    inner = _extract_inner_string("GetDoctorCareerResult", r.text)
    if not inner:
        return {"ok": False, "error": "empty_or_invalid_inner"}

    try:
        x = ET.fromstring(inner)
    except ET.ParseError:
        return {"ok": False, "error": "invalid_inner_xml"}

    items = [_dict_from_children(n) for n in x.findall('.//DOCTOR_CAREER')]
    if not items:
        n = x.find('.//DOCTOR_CAREER')
        if n is not None:
            items = [_dict_from_children(n)]

    return {"ok": True, "career": items}

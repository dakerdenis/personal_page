import logging
import re
import xml.etree.ElementTree as ET
from html import unescape as html_unescape
from xml.sax.saxutils import escape as xml_escape
import requests
from django.conf import settings

logger = logging.getLogger('cabinet.auth')

SOAP11_GET_POLICIES = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetCustomerPolicies xmlns="http://tempuri.org/">
      <userName>{user}</userName>
      <password>{password}</password>
      <pinCode>{pin}</pinCode>
    </GetCustomerPolicies>
  </soap:Body>
</soap:Envelope>
'''

SOAP11_GET_POLICY_INFO = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetPolicyInformations xmlns="http://tempuri.org/">
      <userName>{user}</userName>
      <password>{password}</password>
      <policyNumber>{policy}</policyNumber>
    </GetPolicyInformations>
  </soap:Body>
</soap:Envelope>
'''

def _post_soap(url: str, payload: str, action: str, timeout: int, verify_ssl: bool) -> requests.Response:
    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": f"\"http://tempuri.org/{action}\"",
    }
    return requests.post(
        url,
        data=payload.encode('utf-8'),
        headers=headers,
        timeout=timeout,
        verify=verify_ssl,
    )

def _extract_inner_string(tag: str, body: str) -> str | None:
    # Достаём содержимое <tag>...</tag>
    m = re.search(fr'<{tag}[^>]*>(.*?)</{tag}>', body, flags=re.S | re.I)
    if not m:
        return None
    return html_unescape(m.group(1).strip())

def get_customer_policies(pin_code: str) -> dict:
    """
    Возвращает dict: {"ok": True, "policies": [ ... ]} либо {"ok": False, "error": "..."}
    """
    cfg = settings.EXTERNAL_AUTH
    url = cfg['URL']
    timeout = cfg.get('TIMEOUT', 15)
    verify_ssl = cfg.get('VERIFY_SSL', True)

    payload = SOAP11_GET_POLICIES.format(
        user=xml_escape(cfg['USERNAME']),
        password=xml_escape(cfg['PASSWORD']),
        pin=xml_escape(pin_code.strip()),
    )

    try:
        r = _post_soap(url, payload, action="GetCustomerPolicies", timeout=timeout, verify_ssl=verify_ssl)
    except requests.RequestException as e:
        logger.exception("HTTP error during GetCustomerPolicies")
        return {"ok": False, "error": f"http_error: {e}"}

    if r.status_code != 200:
        logger.error("GetCustomerPolicies non-200: %s", r.status_code)
        return {"ok": False, "error": f"http_status_{r.status_code}"}

    inner = _extract_inner_string("GetCustomerPoliciesResult", r.text) \
            or _extract_inner_string("string", r.text)
    if not inner:
        return {"ok": False, "error": "empty_or_invalid_inner"}

    # Внутри снова XML: <DocumentElement><POLICIES>...</POLICIES></DocumentElement>
    try:
        x = ET.fromstring(inner)
    except ET.ParseError:
        return {"ok": False, "error": "invalid_inner_xml"}

    # Полисы могут быть массивом или одной записью
    policies = []
    for node in x.findall('.//POLICIES'):
        item = {child.tag: (child.text or '').strip() for child in list(node)}
        policies.append(item)

    if not policies:
        # Иногда формат другой: POLICIES/... внутри
        parent = x.find('.//POLICIES')
        if parent is not None:
            item = {child.tag: (child.text or '').strip() for child in list(parent)}
            policies = [item] if item else []

    return {"ok": True, "policies": policies}

def get_policy_informations(policy_number: str) -> dict:
    """
    Возвращает {"ok": True, "data": {...}} или {"ok": False, "error": "..."}
    """
    cfg = settings.EXTERNAL_AUTH
    url = cfg['URL']
    timeout = cfg.get('TIMEOUT', 15)
    verify_ssl = cfg.get('VERIFY_SSL', True)

    payload = SOAP11_GET_POLICY_INFO.format(
        user=xml_escape(cfg['USERNAME']),
        password=xml_escape(cfg['PASSWORD']),
        policy=xml_escape(policy_number.strip()),
    )

    try:
        r = _post_soap(url, payload, action="GetPolicyInformations", timeout=timeout, verify_ssl=verify_ssl)
    except requests.RequestException as e:
        logger.exception("HTTP error during GetPolicyInformations")
        return {"ok": False, "error": f"http_error: {e}"}

    if r.status_code != 200:
        logger.error("GetPolicyInformations non-200: %s", r.status_code)
        return {"ok": False, "error": f"http_status_{r.status_code}"}

    inner = _extract_inner_string("GetPolicyInformationsResult", r.text) \
            or _extract_inner_string("string", r.text)
    if not inner:
        return {"ok": False, "error": "empty_or_invalid_inner"}

    try:
        x = ET.fromstring(inner)
    except ET.ParseError:
        return {"ok": False, "error": "invalid_inner_xml"}

    # Превратим одну ступень XML в dict (плоско)
    data = {}
    for child in list(x):
        # Если вложенные коллекции (например, COLLATERAL_NAMES), соберём списком
        if list(child):
            if child.tag.upper() == 'COLLATERAL_NAMES':
                data['COLLATERAL_NAMES'] = [
                    {cc.tag: (cc.text or '').strip() for cc in list(item)}
                    for item in child.findall('./*')
                ]
            else:
                data[child.tag] = {cc.tag: (cc.text or '').strip() for cc in list(child)}
        else:
            data[child.tag] = (child.text or '').strip()

    return {"ok": True, "data": data}

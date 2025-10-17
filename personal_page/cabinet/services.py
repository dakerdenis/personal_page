import logging
import re
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape as xml_escape
from html import unescape as html_unescape  # ← добавили
import requests
from django.conf import settings


logger = logging.getLogger('cabinet.auth')

SOAP12_TEMPLATE = '''<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                 xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                 xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
  <soap12:Body>
    <Login xmlns="http://tempuri.org/">
      <userName>{user}</userName>
      <password>{password}</password>
      <pinCode>{pin}</pinCode>
      <policyNumber>{policy}</policyNumber>
      <phoneNumber>{phone}</phoneNumber>
    </Login>
  </soap12:Body>
</soap12:Envelope>
'''

SOAP11_TEMPLATE = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Login xmlns="http://tempuri.org/">
      <userName>{user}</userName>
      <password>{password}</password>
      <pinCode>{pin}</pinCode>
      <policyNumber>{policy}</policyNumber>
      <phoneNumber>{phone}</phoneNumber>
    </Login>
  </soap:Body>
</soap:Envelope>
'''

def _extract_inner_xml_from_soap(resp_text: str) -> str | None:
    m = re.search(r'<LoginResult>(.*?)</LoginResult>', resp_text, flags=re.S | re.I)
    if m:
        inner = m.group(1).strip()
        # иногда и тут бывает экранирование
        inner = html_unescape(inner).strip()
        return inner if inner else None

    m2 = re.search(r'<string\b[^>]*>(.*?)</string>', resp_text, flags=re.S | re.I)
    if m2:
        inner = m2.group(1)
        inner = html_unescape(inner).strip()
        return inner if inner else None

    try:
        root = ET.fromstring(resp_text)
        text = (root.text or '').strip()
        text = html_unescape(text).strip()
        return text if text else None
    except ET.ParseError:
        return None


def _parse_login_result_xml(inner_xml: str) -> dict:
    result = {"ok": False, "name": None, "surname": None, "error": None}
    try:
        x = ET.fromstring(inner_xml)
    except ET.ParseError:
        result["error"] = "invalid_inner_xml"
        return result

    login_node = x.find('.//LOGIN')
    error_node = x.find('.//ERROR')

    if login_node is not None:
        is_logged = (login_node.findtext('IS_LOGGED') or '').strip()
        name = (login_node.findtext('NAME') or '').strip()
        surname = (login_node.findtext('SURNAME') or '').strip()
        if is_logged == '1':
            result.update({"ok": True, "name": name, "surname": surname})
            return result
        result["error"] = "not_logged"
        return result

    if error_node is not None:
        msg = (error_node.findtext('MESSAGE') or '').strip()
        result["error"] = msg or "unknown_error"
        return result

    result["error"] = "unrecognized_response"
    return result

def _do_post(url: str, payload: str, headers: dict, verify_ssl: bool, timeout: int) -> requests.Response:
    return requests.post(
        url,
        data=payload.encode('utf-8'),
        headers=headers,
        timeout=timeout,
        verify=verify_ssl,
    )

def external_login(pin: str, policy: str, phone: str) -> dict:
    cfg = settings.EXTERNAL_AUTH
    url = cfg['URL']
    timeout = cfg.get('TIMEOUT', 15)
    verify_ssl = cfg.get('VERIFY_SSL', True)

    # ЭКРАНИРУЕМ ВСЕ ПОЛЯ ДЛЯ XML !!!
    user = xml_escape(cfg['USERNAME'])
    password = xml_escape(cfg['PASSWORD'])
    pin_e = xml_escape(pin)
    policy_e = xml_escape(policy)
    phone_e = xml_escape(phone)

    logger.info(f"Login request: pin={pin}, policy={policy}, phone={phone}")

    # --- Попытка №1: SOAP 1.2 ---
    payload12 = SOAP12_TEMPLATE.format(user=user, password=password, pin=pin_e, policy=policy_e, phone=phone_e)
    headers12 = {
        "Content-Type": "application/soap+xml; charset=utf-8",
        # Для некоторых серверов полезно: "action" в Content-Type, но сначала пробуем без
        # Пример при необходимости:
        # "Content-Type": 'application/soap+xml; charset=utf-8; action="http://tempuri.org/Login"',
    }
    try:
        r = _do_post(url, payload12, headers12, verify_ssl, timeout)
    except requests.RequestException as e:
        logger.exception("HTTP error during SOAP12 call")
        return {"ok": False, "error": f"http_error: {e}", "name": None, "surname": None}

    if r.status_code == 200:
        inner = _extract_inner_xml_from_soap(r.text)
        if not inner:
            logger.error("SOAP12: cannot extract inner XML")
            return {"ok": False, "error": "empty_or_invalid_inner", "name": None, "surname": None}
        parsed = _parse_login_result_xml(inner)
        logger.info(f"SOAP12 parsed: {parsed}")
        return parsed

    logger.error("SOAP12 Non-200: %s; body: %s", r.status_code, r.text[:800])

    # --- Попытка №2: SOAP 1.2 с action в Content-Type (некоторые так требуют) ---
    headers12_action = {
        "Content-Type": 'application/soap+xml; charset=utf-8; action="http://tempuri.org/Login"',
    }
    try:
        r2 = _do_post(url, payload12, headers12_action, verify_ssl, timeout)
    except requests.RequestException as e:
        logger.exception("HTTP error during SOAP12(action) call")
        return {"ok": False, "error": f"http_error: {e}", "name": None, "surname": None}

    if r2.status_code == 200:
        inner = _extract_inner_xml_from_soap(r2.text)
        if not inner:
            logger.error("SOAP12(action): cannot extract inner XML")
            return {"ok": False, "error": "empty_or_invalid_inner", "name": None, "surname": None}
        parsed = _parse_login_result_xml(inner)
        logger.info(f"SOAP12(action) parsed: {parsed}")
        return parsed

    logger.error("SOAP12(action) Non-200: %s; body: %s", r2.status_code, r2.text[:800])

    # --- Попытка №3: SOAP 1.1 (часто этот эндпоинт ждёт именно 1.1) ---
    payload11 = SOAP11_TEMPLATE.format(user=user, password=password, pin=pin_e, policy=policy_e, phone=phone_e)
    headers11 = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": '"http://tempuri.org/Login"',
    }
    try:
        r3 = _do_post(url, payload11, headers11, verify_ssl, timeout)
    except requests.RequestException as e:
        logger.exception("HTTP error during SOAP11 call")
        return {"ok": False, "error": f"http_error: {e}", "name": None, "surname": None}

    if r3.status_code != 200:
        logger.error("SOAP11 Non-200: %s; body: %s", r3.status_code, r3.text[:800])
        return {"ok": False, "error": f"http_status_{r3.status_code}", "name": None, "surname": None}

    inner = _extract_inner_xml_from_soap(r3.text)
    if not inner:
        logger.error("SOAP11: cannot extract inner XML")
        return {"ok": False, "error": "empty_or_invalid_inner", "name": None, "surname": None}

    parsed = _parse_login_result_xml(inner)
    logger.info(f"SOAP11 parsed: {parsed}")
    return parsed

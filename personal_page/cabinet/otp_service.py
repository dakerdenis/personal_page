import logging
import re
import xml.etree.ElementTree as ET
from html import unescape as html_unescape
from xml.sax.saxutils import escape as xml_escape
import requests
from django.conf import settings

logger = logging.getLogger('cabinet.auth')

SOAP12_OTP = '''<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                 xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                 xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
  <soap12:Body>
    <CreateOTPAndSendSMS xmlns="http://tempuri.org/">
      <userName>{user}</userName>
      <password>{password}</password>
      <phoneNumber>{phone}</phoneNumber>
    </CreateOTPAndSendSMS>
  </soap12:Body>
</soap12:Envelope>
'''

SOAP11_OTP = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <CreateOTPAndSendSMS xmlns="http://tempuri.org/">
      <userName>{user}</userName>
      <password>{password}</password>
      <phoneNumber>{phone}</phoneNumber>
    </CreateOTPAndSendSMS>
  </soap:Body>
</soap:Envelope>
'''

def _extract_inner(resp_text: str) -> str | None:
    m = re.search(r'<CreateOTPAndSendSMSResult>(.*?)</CreateOTPAndSendSMSResult>', resp_text, flags=re.S|re.I)
    if m:
        return html_unescape(m.group(1).strip()) or None
    m2 = re.search(r'<string\b[^>]*>(.*?)</string>', resp_text, flags=re.S|re.I)
    if m2:
        return html_unescape(m2.group(1).strip()) or None
    try:
        root = ET.fromstring(resp_text)
        t = (root.text or '').strip()
        return html_unescape(t).strip() or None
    except ET.ParseError:
        return None

def _parse_otp_inner(inner_xml: str) -> dict:

    result = {"ok": False, "code": None, "error": None}
    try:
        x = ET.fromstring(inner_xml)
    except ET.ParseError:
        result["error"] = "invalid_inner_xml"
        return result

    otp = x.find('.//OTP')
    err = x.find('.//ERROR')
    if otp is not None:
        code = (otp.findtext('Code') or '').strip()
        status = (otp.findtext('Result') or '').strip().upper()
        if status == 'OK' and code:
            result.update({"ok": True, "code": code})
            return result
        result["error"] = f"otp_status_{status or 'unknown'}"
        return result
    if err is not None:
        msg = (err.findtext('MESSAGE') or '').strip()
        result["error"] = msg or "unknown_error"
        return result

    result["error"] = "unrecognized_response"
    return result

def _post(url: str, payload: str, headers: dict, verify: bool, timeout: int) -> requests.Response:
    return requests.post(url, data=payload.encode('utf-8'), headers=headers, verify=verify, timeout=timeout)

def create_otp_and_send_sms(phone: str) -> dict:
    cfg = settings.EXTERNAL_AUTH
    url = cfg['URL']
    timeout = cfg.get('TIMEOUT', 15)
    verify_ssl = cfg.get('VERIFY_SSL', True)

    user = xml_escape(cfg['USERNAME'])
    password = xml_escape(cfg['PASSWORD'])
    phone_e = xml_escape(phone)

    logger.info(f"OTP request to {phone}")


    payload12 = SOAP12_OTP.format(user=user, password=password, phone=phone_e)
    headers12 = { "Content-Type": "application/soap+xml; charset=utf-8" }
    try:
        r = _post(url, payload12, headers12, verify_ssl, timeout)
        if r.status_code == 200:
            inner = _extract_inner(r.text)
            if not inner:
                logger.error("OTP SOAP12: cannot extract inner; head: %s", r.text[:600])
                return {"ok": False, "error": "empty_or_invalid_inner", "code": None}
            parsed = _parse_otp_inner(inner)
            logger.info(f"OTP SOAP12 parsed: {parsed}")
            return parsed
        logger.error("OTP SOAP12 Non-200: %s; head: %s", r.status_code, r.text[:600])
    except requests.RequestException as e:
        logger.exception("OTP SOAP12 http_error: %s", e)


    payload11 = SOAP11_OTP.format(user=user, password=password, phone=phone_e)
    headers11 = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": '"http://tempuri.org/CreateOTPAndSendSMS"',
    }
    try:
        r2 = _post(url, payload11, headers11, verify_ssl, timeout)
        if r2.status_code != 200:
            logger.error("OTP SOAP11 Non-200: %s; head: %s", r2.status_code, r2.text[:600])
            return {"ok": False, "error": f"http_status_{r2.status_code}", "code": None}
        inner = _extract_inner(r2.text)
        if not inner:
            logger.error("OTP SOAP11: cannot extract inner; head: %s", r2.text[:600])
            return {"ok": False, "error": "empty_or_invalid_inner", "code": None}
        parsed = _parse_otp_inner(inner)
        logger.info(f"OTP SOAP11 parsed: {parsed}")
        return parsed
    except requests.RequestException as e:
        logger.exception("OTP SOAP11 http_error: %s", e)
        return {"ok": False, "error": f"http_error: {e}", "code": None}

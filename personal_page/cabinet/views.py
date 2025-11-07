import io, random, string, re
from django.shortcuts import render, redirect
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from django.contrib import messages
from django.http import HttpRequest, HttpResponse
from PIL import Image, ImageDraw, ImageFont, ImageFilter

# твоё уже есть:
from .services import external_login
from .otp_service import create_otp_and_send_sms
from .complaint_service import get_medical_claim_informations  # если используешь
from .complaint_not_service import get_non_medical_complaints

from django.http import JsonResponse
from django.views.decorators.http import require_GET, require_POST

from .policy_service import get_customer_policies, get_policy_informations
from .doctor_service import (
    get_specialities,
    get_doctors_by_speciality,
    get_doctor_career,   # ← ЭТОГО не хватало
)
from .doctor_service import registration_for_doctor 

OTP_TTL_SECONDS = 60
OTP_MAX_ATTEMPTS = 3

INSURANCE_TITLES = {
    "AATPL":"Avtomobilin İcbari Sığortası",
    "AS":"Avtomobilin Kasko Sığortası", "VMI":"Avtomobilin Kasko Sığortası",
    "AS-A47-GD":"Avtomobilin Kasko Sığortası", "AS-FQ":"Avtomobilin Kasko Sığortası",
    "AS-F":"Avtomobilin Kasko Sığortası", "AS-H":"Avtomobilin Kasko Sığortası", "REVAS":"Avtomobilin Kasko Sığortası",
    "EE":"Elektron cihazların sığortası",
    "DETPL":"Əmlak İstismarın İcbari Sığortası", "DE":"Əmlakın İcbari Sığortası",
    "VHI":"Əmlakın könüllü sığortası", "VPI-FL":"Əmlakın könüllü sığortası", "VPI-F":"Əmlakın könüllü sığortası",
    "VPI-H":"Əmlakın könüllü sığortası", "VPI":"Əmlakın könüllü sığortası",
    "VPI-HN":"Əmlakın könüllü sığortası", "VPI-FN":"Əmlakın könüllü sığortası", "REVPI":"Əmlakın könüllü sığortası",
    "CPA":"Fərdi qəza sığortası", "PA":"Fərdi qəza sığortası",
    "CAR":"İnşaat risklərin sığортası",
    "EL":"İşəgötürənin məsuliyyətinin sığortası", "ELN":"İşəgötürənin məsuliyyətinin sığортası",
    "TPL":"Məsuliyyət sığortası", "TPLN":"Məsuliyyət sığортası",
    "CMMI":"Peşə Məsuliyyətinin sığортası", "PI":"Peşə Məsuliyyətinin sığортası", "CDOL":"Peşə Məsuliyyətinin sığортası",
    "CPM":"Podratçının maşın və avadanlığın sığортası",
    "TI":"Səyahət sığортası",
    "VPI-R":"Təkərlərin sığортası",
    "LI":"Tibbi Sığorta", "LE":"Tibbi Sığorta", "ONK-A47":"Tibbi Sığorta", "ONK":"Tibbi Sığorta",
    "TTU":"Tibbi Sığorta", "LE-D":"Tibbi Sığorta",
    "YK":"Yaşıl Kart", "YS-OC":"Yük sığортası", "YS":"Yük sığортası", "YSN":"Yük sığортası",
}

MEDICAL_CODES = {"LI","LE","ONK-A47","ONK","TTU","LE-D","YK","YS-OC","YS","YSN"}

CAR_CODES = {"AATPL","AS","VMI","AS-A47-GD","AS-FQ","AS-F","AS-H","REVAS"}
STATUS_TITLES = {"B":"Bitdi","D":"Davam Edir","E":"Sonlandırıldı"}

def index(request: HttpRequest):
    if not request.session.get('loggedin'):
        return redirect('login')
    name = request.session.get('name') or ''
    surname = request.session.get('surname') or ''
    return render(request, 'cabinet/index.html', {'name': name, 'surname': surname})


@require_http_methods(["GET", "POST"])
def login_view(request: HttpRequest):
    # капча по количеству неудачных логинов (этап Шаг 1)
    attempts = int(request.session.get('login_attempts', 0))
    need_captcha = attempts >= 3

    # уже вошёл?
    if request.session.get('loggedin'):
        return redirect('cabinet_welcome')

    # состояние OTP
    otp_pending    = request.session.get('otp_pending', False)
    otp_expires_at = request.session.get('otp_expires_at')  # epoch
    now_ts         = int(timezone.now().timestamp())

    # ----- Если есть живой OTP — показываем форму OTP (и только её) -----
    if otp_pending and otp_expires_at and now_ts < int(otp_expires_at):
        if request.method == 'POST' and 'otp_code' in request.POST:
            # ВАЛИДАЦИЯ OTP
            user_code   = (request.POST.get('otp_code') or '').strip()
            real_code   = request.session.get('otp_code') or ''
            otp_attempt = int(request.session.get('otp_attempts', 0))

            # истёк?
            if now_ts >= int(otp_expires_at):
                _reset_session_to_login(request)
                messages.error(request, "OTP daxil etmə vaxtı bitdi.")
                return redirect('login')

            # пусто?
            if not user_code:
                messages.error(request, "Zəhmət olmasa OTP kodunu daxil edin.")
                remaining = int(otp_expires_at) - now_ts
                return _render_otp(request, remaining=remaining)

            # верный код — логиним
            if user_code == real_code:
                request.session['loggedin'] = True
                # чистим все otp-поля
                for k in ['otp_code','otp_pending','otp_attempts','otp_expires_at','otp_sent_at']:
                    request.session.pop(k, None)
                # и счётчик логин-попыток
                request.session['login_attempts'] = 0
                return redirect('cabinet_welcome')

            # неверный код
            otp_attempt += 1
            request.session['otp_attempts'] = otp_attempt
            if otp_attempt >= OTP_MAX_ATTEMPTS:
                _reset_session_to_login(request)
                messages.error(request, "Cəhdlərin sayı aşıldı. Zəhmət olmasa yenidən daxil olun.")
                return redirect('login')

            messages.error(request, f"Səhv kod. Qalan cəhdlər: {OTP_MAX_ATTEMPTS - otp_attempt}.")
            remaining = int(otp_expires_at) - now_ts
            return _render_otp(request, remaining=max(0, remaining))

        # GET (или POST без otp_code) — просто показать форму с актуальным оставшимся временем
        return _render_otp(request, remaining=max(0, int(otp_expires_at) - now_ts))

    # ----- Здесь OTP нет или истёк: стандартный Шаг 1 (проверка логина) -----
    if request.method == 'POST':
        pin    = (request.POST.get('pinCode') or '').strip()
        policy = (request.POST.get('policyNumber') or '').strip()
        phone  = (request.POST.get('phoneNumber') or '').strip()

        if not (pin and policy and phone):
            messages.error(request, "Bütün sahələr doldurulmalıdır.")
            return render(request, 'cabinet/login.html', {"need_captcha": need_captcha})

        # если капча нужна — проверяем
        if need_captcha:
            user_captcha = (request.POST.get('captcha') or '').strip()
            real_captcha = request.session.get('captcha_code', '')
            if not user_captcha or user_captcha != real_captcha:
                messages.error(request, "CAPTCHA düzgün daxil edilməyib.")
                return render(request, 'cabinet/login.html', {"need_captcha": True})

        # Проверка логина на внешнем SOAP (без авторизации)
        result = external_login(pin=pin, policy=policy, phone=phone)

        if result.get('ok'):
            # УСПЕХ: отправляем OTP РОВНО ОДИН РАЗ и фиксируем состояние
            otp_resp = create_otp_and_send_sms(phone=phone)
            if not otp_resp.get('ok'):
                messages.error(request, f"OTP göndərilə bilmədi: {otp_resp.get('error')}")
                return render(request, 'cabinet/login.html', {"need_captcha": need_captcha})

            request.session['name']      = result.get('name') or ''
            request.session['surname']   = result.get('surname') or ''
            request.session['phoneNumber'] = phone
            request.session['pinCode']     = pin

            request.session['otp_code']      = otp_resp.get('code')
            request.session['otp_attempts']  = 0
            request.session['otp_pending']   = True
            request.session['otp_expires_at']= now_ts + OTP_TTL_SECONDS
            request.session['otp_sent_at']   = now_ts

            # сбросим счётчик логин-провалов
            request.session['login_attempts'] = 0

            return _render_otp(request, remaining=OTP_TTL_SECONDS)

        # ошибка логина → увеличиваем счётчик (для капчи)
        attempts += 1
        request.session['login_attempts'] = attempts

        normalize = {
            'user_not_found'        : 'İstifadəçi tapılmadı.',
            'incorrect_phone_number': 'Telefon nömrəsi yanlışdır.',
            'repeated_phone_number' : 'Bu nömrə artıq istifadə olunur.',
            'not_logged'            : 'Daxil edilən məlumatlar səhvdir. Zəhmət olmasa yoxlayın.',
            'invalid_inner_xml'     : 'Serverdən səhv cavab alındı.',
            'unrecognized_response' : 'Serverdən naməlum cavab alındı.',
            'login_failed'          : 'Daxil olmaq alınmadı.',
        }
        err = (result.get('error') or 'login_failed').strip()
        messages.error(request, normalize.get(err, err))
        return render(request, 'cabinet/login.html', {"need_captcha": attempts >= 3})

    # GET: если висел просроченный OTP — подчистим и покажем логин
    if otp_pending and otp_expires_at and now_ts >= int(otp_expires_at):
        _reset_session_to_login(request)
        messages.error(request, "OTP daxil etmə vaxtı bitdi.")

    return render(request, 'cabinet/login.html', {"need_captcha": need_captcha})


def logout_view(request: HttpRequest):
    request.session.flush()
    return redirect('login')
# --- helpers ---
def _render_otp(request: HttpRequest, remaining: int):
    return render(request, 'cabinet/otp.html', {
        "remaining": max(0, int(remaining)),
        "phone": request.session.get('phoneNumber', ''),
        "name": request.session.get('name', ''),
        "surname": request.session.get('surname', ''),
        "max_attempts": OTP_MAX_ATTEMPTS,
        "attempts_left": OTP_MAX_ATTEMPTS - int(request.session.get('otp_attempts', 0)),
    })

def _reset_session_to_login(request: HttpRequest):
    for k in ['otp_code', 'otp_pending', 'otp_attempts', 'otp_expires_at',
              'pinCode', 'phoneNumber', 'name', 'surname', 'loggedin']:
        request.session.pop(k, None)

def _guard(request):
    if not request.session.get('loggedin'):
        return False
    return True

def _ctx(request, active):
    return {
        "name": request.session.get('name', ''),
        "surname": request.session.get('surname', ''),
        "active": active,
    }

def welcome(request: HttpRequest):
    if not _guard(request): return redirect('login')
    return render(request, 'cabinet/welcome.html', _ctx(request, 'welcome'))

def policies(request: HttpRequest):
    if not request.session.get('loggedin'):
        return redirect('login')
    return render(request, 'cabinet/policies.html', {
        "name": request.session.get('name', ''),
        "surname": request.session.get('surname', ''),
        "active": "policies",
    })

@require_GET
def api_policies(request: HttpRequest):
    if not request.session.get('loggedin'):
        return JsonResponse({"error": "unauthorized"}, status=401)
    pin = request.session.get('pinCode', '')
    if not pin:
        return JsonResponse({"error": "no_pin_in_session"}, status=400)
    result = get_customer_policies(pin)
    return JsonResponse(result, status=200 if result.get("ok") else 502)

@require_POST
def api_policy_info(request: HttpRequest):
    if not request.session.get('loggedin'):
        return JsonResponse({"error": "unauthorized"}, status=401)
    policy_number = (request.POST.get('policyNumber') or '').strip()
    if not policy_number:
        return JsonResponse({"error": "policy_number_required"}, status=400)
    result = get_policy_informations(policy_number)
    return JsonResponse(result, status=200 if result.get("ok") else 502)

def policy_detail(request: HttpRequest, policy_number: str):
    if not request.session.get('loggedin'):
        return redirect('login')

    r = get_policy_informations(policy_number)
    if not r.get("ok"):
        messages.error(request, f"Polis yüklənmədi: {r.get('error')}")
        return redirect('cabinet_policies')

    d = r.get("data") or {}
    code = (d.get("INSURANCE_CODE") or "").strip()

    # ← ДОБАВЛЕНО: если код/статус не пришли из detail-метода — добираем из общего списка
    if not code or not d.get("STATUS"):
        pin = request.session.get('pinCode', '')
        if pin:
            lst = get_customer_policies(pin)
            if lst.get("ok"):
                for p in lst.get("policies", []):
                    if (p.get("POLICY_NUMBER") or "").strip() == policy_number:
                        code = (p.get("INSURANCE_CODE") or code or "").strip()
                        if not d.get("STATUS"):
                            d["STATUS"] = (p.get("STATUS") or "").strip()
                        break

    # заголовок «Нöv» и статус
    policy_title = INSURANCE_TITLES.get(code, (code or "")) or ""
    status_title = STATUS_TITLES.get((d.get("STATUS") or "").strip(), d.get("STATUS") or "")

    # ← ДОБАВЛЕНО: эвристики на случай, если кода всё ещё нет
    inferred_car = any(d.get(k) for k in ("BRAND_NAME","MODEL_NAME","PLATE_NUMBER_FULL"))
    inferred_med = any(d.get(k) for k in ("INSURER_CUSTOMER_NAME","INSURED_CUSTOMER_NAME","PROGRAM_NAME"))

    is_car = (code in CAR_CODES) or inferred_car
    is_medical = (code in MEDICAL_CODES) or (not is_car and inferred_med)

    # Фолбэк названия, если кода так и нет
    if not policy_title:
        policy_title = "Avtomobil sığortası" if is_car else ("Tibbi Sığorta" if is_medical else "—")

    return render(request, 'cabinet/policy_detail.html', {
        "name": request.session.get('name', ''),
        "surname": request.session.get('surname', ''),
        "active": "policies",
        "policy": d,
        "policy_number": policy_number,
        "policy_title": policy_title,
        "status_title": status_title,
        "is_medical": is_medical,
        "is_car": is_car,
    })

def doctors(request: HttpRequest):
    if not request.session.get('loggedin'):
        return redirect('login')
    return render(request, 'cabinet/doctors.html', {
        "name": request.session.get('name', ''),
        "surname": request.session.get('surname', ''),
        "active": "doctors",
    })

@require_GET
def api_specialities(request: HttpRequest):
    if not request.session.get('loggedin'):
        return JsonResponse({"error": "unauthorized"}, status=401)
    result = get_specialities()
    return JsonResponse(result, status=200 if result.get("ok") else 502)

def doctors_by_speciality(request: HttpRequest, speciality_id: str):
    if not request.session.get('loggedin'):
        return redirect('login')
    return render(request, 'cabinet/doctors_speciality.html', {
        "name": request.session.get('name', ''),
        "surname": request.session.get('surname', ''),
        "active": "doctors",
        "speciality_id": speciality_id,
    })

@require_GET
def api_doctors_by_speciality(request: HttpRequest, speciality_id: str):
    if not request.session.get('loggedin'):
        return JsonResponse({"error": "unauthorized"}, status=401)
    result = get_doctors_by_speciality(speciality_id)
    return JsonResponse(result, status=200 if result.get("ok") else 502)

def doctor_detail(request: HttpRequest, speciality_id: str, doctor_id: str):
    if not request.session.get('loggedin'):
        return redirect('login')
    return render(request, 'cabinet/doctor_detail.html', {
        "name": request.session.get('name', ''),
        "surname": request.session.get('surname', ''),
        "active": "doctors",
        "speciality_id": speciality_id,
        "doctor_id": doctor_id,
    })


@require_GET
def api_doctor_career(request: HttpRequest, doctor_id: str):
    if not request.session.get('loggedin'):
        return JsonResponse({"ok": False, "error": "unauthorized"}, status=401)
    try:
        result = get_doctor_career(doctor_id)
    except Exception as e:
        # не даём упасть до HTML-500
        return JsonResponse({"ok": False, "error": f"internal_error: {e}"}, status=500)
    return JsonResponse(result, status=200 if result.get("ok") else 502)

def complaints(request: HttpRequest):
    if not request.session.get('loggedin'):
        return redirect('login')
    return render(request, 'cabinet/complaints.html', {
        "name": request.session.get('name', ''),
        "surname": request.session.get('surname', ''),
        "active": "complaints",
    })

@require_GET
def api_medical_complaints(request: HttpRequest):
    if not request.session.get('loggedin'):
        return JsonResponse({"ok": False, "error": "unauthorized"}, status=401)
    pin = request.session.get('pinCode', '')
    if not pin:
        return JsonResponse({"ok": False, "error": "no_pin_in_session"}, status=400)
    result = get_medical_claim_informations(pin)
    return JsonResponse(result, status=200 if result.get("ok") else 502)

def complaints_not_medical(request: HttpRequest):
    # простая защита — пускаем только после логина
    if not request.session.get('loggedin'):
        return redirect('login')
    # активная вкладка — чтобы меню подсветилось как в других страницах
    ctx = {
        "name": request.session.get('name', ''),
        "surname": request.session.get('surname', ''),
        "active": "complaints_not_medical",
    }
    return render(request, 'cabinet/complaints_not_medical.html', ctx)

@require_GET
def api_non_medical_complaints(request: HttpRequest):
    if not request.session.get('loggedin'):
        return JsonResponse({"error": "unauthorized"}, status=401)
    pin = request.session.get('pinCode', '')
    if not pin:
        return JsonResponse({"error": "no_pin_in_session"}, status=400)
    r = get_non_medical_complaints(pin)
    return JsonResponse(r, status=200 if r.get("ok") else 502)

def refund(request: HttpRequest):
    if not _guard(request): return redirect('login')
    return render(request, 'cabinet/refund.html', _ctx(request, 'refund'))

def captcha_image(request: HttpRequest):
    import random, string, io
    from PIL import Image, ImageDraw, ImageFont, ImageFilter
    from django.http import HttpResponse

    # создаём код и кладём в сессию
    code = ''.join(random.choices(string.digits, k=5))
    request.session['captcha_code'] = code

    # размеры
    W, H = 130, 46
    img = Image.new('RGB', (W, H), (255, 255, 255))
    draw = ImageDraw.Draw(img)

    # выбираем шрифт
    try:
        font = ImageFont.truetype("arial.ttf", 28)
    except Exception:
        font = ImageFont.load_default()

    # --- шум: точки + линии ---
    for _ in range(180):
        x = random.randint(0, W)
        y = random.randint(0, H)
        draw.point((x, y), fill=(random.randint(100, 200), random.randint(100, 200), random.randint(100, 200)))

    # тонкие линии фона
    for _ in range(5):
        x1, y1 = random.randint(0, W), random.randint(0, H)
        x2, y2 = random.randint(0, W), random.randint(0, H)
        color = (random.randint(100, 180), random.randint(100, 180), random.randint(100, 180))
        draw.line(((x1, y1), (x2, y2)), fill=color, width=random.randint(1, 2))

    # --- текст (слегка случайное положение каждой цифры) ---
    start_x = 15
    for ch in code:
        offset_y = random.randint(-4, 4)
        draw.text((start_x, 10 + offset_y), ch, font=font, fill=(random.randint(0, 60),)*3)
        start_x += 22

    # лёгкое размытие и искажения
    img = img.filter(ImageFilter.SMOOTH_MORE)
    img = img.filter(ImageFilter.GaussianBlur(radius=0.4))

    # отдаём
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return HttpResponse(buf.getvalue(), content_type="image/png")


@require_GET
def api_active_med_policies(request: HttpRequest):
    if not request.session.get('loggedin'):
        return JsonResponse({"ok": False, "error": "unauthorized"}, status=401)
    pin = request.session.get('pinCode') or ''
    if not pin:
        return JsonResponse({"ok": False, "error": "no_pin_in_session"}, status=400)

    r = get_customer_policies(pin)
    if not r.get("ok"):
        return JsonResponse({"ok": False, "error": r.get("error") or "policies_failed"}, status=502)

    items = r.get("policies") or []
    out = []
    for it in items:
        code = (it.get("INSURANCE_CODE") or "").strip()
        status = (it.get("STATUS") or "").strip()  # "D" — активен у тебя ранее
        if code in MEDICAL_CODES and status in {"D",""}:
            # попытаемся вытащить cardNumber вида 123456/78 из любых полей
            card = ""
            for v in it.values():
                if isinstance(v, str):
                    m = re.search(r'\d{6}\/\d{2}', v)
                    if m:
                        card = m.group(0)
                        break
            out.append({
                "policy_number": it.get("POLICY_NUMBER") or "",
                "card_number": card,  # может быть пустым, фронт предупредит
                "program": it.get("PROGRAM_NAME") or "",
                "start": (it.get("INSURANCE_START_DATE") or "")[:10],
            })
    return JsonResponse({"ok": True, "policies": out}, status=200)

@require_POST
def api_register_doctor(request: HttpRequest):
    if not request.session.get('loggedin'):
        return JsonResponse({"ok": False, "error": "unauthorized"}, status=401)

    pin   = request.session.get('pinCode') or ''
    card  = (request.POST.get('cardNumber') or '').strip()
    docid = (request.POST.get('doctorId') or '').strip()

    if not (pin and card and docid):
        return JsonResponse({"ok": False, "error": "missing_params"}, status=400)

    res = registration_for_doctor(pin, card, docid)
    return JsonResponse(res, status=200 if res.get("ok") else 502)






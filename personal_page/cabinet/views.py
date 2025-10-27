from django.shortcuts import render, redirect
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from django.contrib import messages
from django.http import HttpRequest
from .services import external_login
from .otp_service import create_otp_and_send_sms

from django.http import JsonResponse
from django.views.decorators.http import require_GET, require_POST

from .policy_service import get_customer_policies, get_policy_informations
from .doctor_service import (
    get_specialities,
    get_doctors_by_speciality,
    get_doctor_career,   # ← ЭТОГО не хватало
)

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
    # Если уже вошёл — на главную
    if request.session.get('loggedin'):
        return redirect('home')

    # Шаг 2: если есть незавершённый OTP — показываем форму OTP и валидируем POST
    otp_pending = request.session.get('otp_pending', False)
    otp_expires_at = request.session.get('otp_expires_at')  # epoch seconds
    now_ts = int(timezone.now().timestamp())

    if request.method == 'POST':
        # Если пришёл POST с полем otp_code — это верификация OTP
        if 'otp_code' in request.POST:
            if not otp_pending:
                return redirect('login')

            if not otp_expires_at or now_ts >= int(otp_expires_at):
                _reset_session_to_login(request)
                messages.error(request, "OTP daxil etmə vaxtı bitdi.")
                return redirect('login')

            user_code = (request.POST.get('otp_code') or '').strip()
            real_code = request.session.get('otp_code') or ''
            attempts = int(request.session.get('otp_attempts', 0))

            if not user_code:
                messages.error(request, "Zəhmət olmasa OTP kodunu daxil edin.")
                return _render_otp(request, remaining=int(otp_expires_at) - now_ts)

            if user_code == real_code:
                # Успех: логиним
                request.session['loggedin'] = True
                # очищаем OTP-промежуточные поля
                for k in ['otp_code', 'otp_pending', 'otp_attempts', 'otp_expires_at']:
                    request.session.pop(k, None)
                return redirect('home')
            else:
                attempts += 1
                request.session['otp_attempts'] = attempts
                if attempts >= OTP_MAX_ATTEMPTS:
                    _reset_session_to_login(request)
                    messages.error(request, "Cəhdlərin sayı aşıldı. Zəhmət olmasa yenidən daxil olun.")
                    return redirect('login')
                messages.error(request, f"Səhv kod. Qalan cəhdlər: {OTP_MAX_ATTEMPTS - attempts}.")
                return _render_otp(request, remaining=int(otp_expires_at) - now_ts)

        # Иначе это шаг 1: обработка логин-формы
        pin = (request.POST.get('pinCode') or '').strip()
        policy = (request.POST.get('policyNumber') or '').strip()
        phone = (request.POST.get('phoneNumber') or '').strip()

        if not (pin and policy and phone):
            messages.error(request, "Bütün sahələr doldurulmalıdır.")
            return render(request, 'cabinet/login.html')

        # ТОЛЬКО проверяем Логин (без авторизации)
        result = external_login(pin=pin, policy=policy, phone=phone)
        if result.get('ok'):
            # Инициализируем OTP
            otp_resp = create_otp_and_send_sms(phone=phone)
            if not otp_resp.get('ok'):
                messages.error(request, f"OTP göndərilə bilmədi: {otp_resp.get('error')}")
                return render(request, 'cabinet/login.html')

            request.session['name'] = result.get('name') or ''
            request.session['surname'] = result.get('surname') or ''
            request.session['phoneNumber'] = phone
            request.session['pinCode'] = pin

            request.session['otp_code'] = otp_resp.get('code')  # в проде НЕ логируем и не показываем
            request.session['otp_attempts'] = 0
            request.session['otp_pending'] = True
            request.session['otp_expires_at'] = now_ts + OTP_TTL_SECONDS

            return _render_otp(request, remaining=OTP_TTL_SECONDS)

        # Ошибка логина
        normalize = {
            'user_not_found': 'İstifadəçi tapılmadı.',
            'incorrect_phone_number': 'Telefon nömrəsi yanlışdır.',
            'not_logged': 'Daxil edilən məlumatlar səhvdir. Zəhmət olmasa yoxlayın.',
            'invalid_inner_xml': 'Serverdən səhv cavab alındı.',
            'unrecognized_response': 'Serverdən naməlum cavab alındı.',
        }
        err = result.get('error') or 'login_failed'
        messages.error(request, normalize.get(err, err))
        return render(request, 'cabinet/login.html')

    # GET
    if otp_pending and otp_expires_at and now_ts < int(otp_expires_at):
        return _render_otp(request, remaining=int(otp_expires_at) - now_ts)

    # Если висел просроченный OTP — чистим и показываем обычный логин
    if otp_pending and otp_expires_at and now_ts >= int(otp_expires_at):
        _reset_session_to_login(request)
        messages.error(request, "OTP daxil etmə vaxtı bitdi.")

    return render(request, 'cabinet/login.html')


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

    # Надёжные извлечения с фолбэками
    code = (d.get("INSURANCE_CODE")
            or d.get("INSURANCE_TYPE_CODE")
            or d.get("INS_CODE")
            or "").strip()

    status_code = (d.get("STATUS")
                   or d.get("POLICY_STATUS")
                   or d.get("STATUS_CODE")
                   or "").strip()

    # Номер полиса из ответа или из URL (как резерв)
    number = (d.get("POLICY_NUMBER") or policy_number).strip()

    return render(request, 'cabinet/policy_detail.html', {
        "name": request.session.get('name', ''),
        "surname": request.session.get('surname', ''),
        "active": "policies",
        "policy": d,
        "policy_number": number,
        "policy_title": INSURANCE_TITLES.get(code, code or "—"),
        "status_title": STATUS_TITLES.get(status_code, status_code or "—"),
        "is_medical": code in MEDICAL_CODES,
        "is_car": code in CAR_CODES,
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
    if not _guard(request): return redirect('login')
    return render(request, 'cabinet/complaints.html', _ctx(request, 'complaints'))

def complaints_not_medical(request: HttpRequest):
    if not _guard(request): return redirect('login')
    return render(request, 'cabinet/complaints_not_medical.html', _ctx(request, 'complaints_not_medical'))

def refund(request: HttpRequest):
    if not _guard(request): return redirect('login')
    return render(request, 'cabinet/refund.html', _ctx(request, 'refund'))
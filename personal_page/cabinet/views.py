from django.shortcuts import render, redirect
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from django.contrib import messages
from django.http import HttpRequest
from .services import external_login
from .otp_service import create_otp_and_send_sms

OTP_TTL_SECONDS = 60
OTP_MAX_ATTEMPTS = 3

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
                messages.error(request, "Время ввода OTP истекло.")
                return redirect('login')

            user_code = (request.POST.get('otp_code') or '').strip()
            real_code = request.session.get('otp_code') or ''
            attempts = int(request.session.get('otp_attempts', 0))

            if not user_code:
                messages.error(request, "Введите OTP код.")
                return _render_otp(request, remaining= int(otp_expires_at) - now_ts)

            if user_code == real_code:
                # Успех: логиним
                request.session['loggedin'] = True
                # очищаем OTP-промежуточные поля
                for k in ['otp_code','otp_pending','otp_attempts','otp_expires_at']:
                    request.session.pop(k, None)
                return redirect('home')
            else:
                attempts += 1
                request.session['otp_attempts'] = attempts
                if attempts >= OTP_MAX_ATTEMPTS:
                    _reset_session_to_login(request)
                    messages.error(request, "Превышено число попыток. Войдите заново.")
                    return redirect('login')
                messages.error(request, f"Неверный код. Осталось попыток: {OTP_MAX_ATTEMPTS - attempts}.")
                return _render_otp(request, remaining= int(otp_expires_at) - now_ts)

        # Иначе это шаг 1: обработка логин-формы
        pin = (request.POST.get('pinCode') or '').strip()
        policy = (request.POST.get('policyNumber') or '').strip()
        phone = (request.POST.get('phoneNumber') or '').strip()

        if not (pin and policy and phone):
            messages.error(request, "Все поля обязательны.")
            return render(request, 'cabinet/login.html')

        # ТОЛЬКО проверяем Логин (без авторизации)
        result = external_login(pin=pin, policy=policy, phone=phone)
        if result.get('ok'):
            # Инициализируем OTP
            otp_resp = create_otp_and_send_sms(phone=phone)
            if not otp_resp.get('ok'):
                messages.error(request, f"Не удалось отправить OTP: {otp_resp.get('error')}")
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
            'user_not_found': 'Пользователь не найден.',
            'incorrect_phone_number': 'Неверный номер телефона.',
            'not_logged': 'Неверные данные. Проверьте поля.',
            'invalid_inner_xml': 'Некорректный ответ сервера.',
            'unrecognized_response': 'Неподдерживаемый ответ сервера.',
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
        messages.error(request, "Время ввода OTP истекло.")

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
    for k in ['otp_code','otp_pending','otp_attempts','otp_expires_at','pinCode','phoneNumber','name','surname','loggedin']:
        request.session.pop(k, None)

from django.urls import path
from . import views

urlpatterns = [
    # страницы
    path('', views.welcome, name='cabinet_welcome'),
    path('policies/', views.policies, name='cabinet_policies'),
    path('doctors/', views.doctors, name='cabinet_doctors'),
    path('doctors/<speciality_id>/', views.doctors_by_speciality, name='cabinet_doctors_by_speciality'),
    path('doctors/<speciality_id>/<doctor_id>/', views.doctor_detail, name='cabinet_doctor_detail'),

    path('complaints/', views.complaints, name='cabinet_complaints'),
    path('complaints-not-medical/', views.complaints_not_medical, name='cabinet_complaints_not_medical'),
    path('refund/', views.refund, name='cabinet_refund'),

    # auth
    path('login', views.login_view, name='login'),
    path('logout', views.logout_view, name='logout'),

    # API
    path('api/policies', views.api_policies, name='api_policies'),
    path('api/policy-info', views.api_policy_info, name='api_policy_info'),
    path('api/specialities', views.api_specialities, name='api_specialities'),
    path('api/doctors/<speciality_id>', views.api_doctors_by_speciality, name='api_doctors_by_speciality'),
    path('api/doctor-career/<doctor_id>', views.api_doctor_career, name='api_doctor_career'),
]

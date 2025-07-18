from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('stats/', views.public_stats, name='public_stats'),
    
    path('api/report-abuse/', views.api_report_abuse, name='api_report_abuse'),
    path('api/protected/', views.protected_resource, name='protected_resource'),
    
    path('rate-limit-status/', views.check_rate_limit_status, name='rate_limit_status'),

    path('', views.public_stats, name='home'),
]
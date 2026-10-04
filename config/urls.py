from django.contrib import admin
from django.http import HttpResponse
from django.urls import path, include


def healthz(request):
    return HttpResponse('ok')


urlpatterns = [
    path('healthz/', healthz),
    path('admin/', admin.site.urls),
    path('api/', include('password.urls')),
]
from django.urls import path
from .views import (
    ConfigStatusView,
    SetupView,
    LoginView,
    ResetKeyView,
    VaultEntryListView,
    EncodePasswordView,
    DecodePasswordView,
    DeleteEntryView,
)

urlpatterns = [
    path('config/', ConfigStatusView.as_view(), name='config-status'),
    path('setup/', SetupView.as_view(), name='setup'),
    path('login/', LoginView.as_view(), name='login'),
    path('reset-key/', ResetKeyView.as_view(), name='reset-key'),
    path('entries/', VaultEntryListView.as_view(), name='entry-list'),
    path('encode/', EncodePasswordView.as_view(), name='encode'),
    path('decode/', DecodePasswordView.as_view(), name='decode'),
    path('entries/<int:pk>/', DeleteEntryView.as_view(), name='entry-delete'),
]
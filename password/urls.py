from django.urls import path
from .views import (
    RegisterView,
    LoginView,
    MeView,
    RecoveryQuestionView,
    VerifyRecoveryView,
    ResetKeyView,
    VaultEntryListView,
    EncodePasswordView,
    DecodePasswordView,
    DeleteEntryView,
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('me/', MeView.as_view(), name='me'),
    path('recovery/question/', RecoveryQuestionView.as_view(), name='recovery-question'),
    path('recovery/verify/', VerifyRecoveryView.as_view(), name='recovery-verify'),
    path('reset-key/', ResetKeyView.as_view(), name='reset-key'),
    path('entries/', VaultEntryListView.as_view(), name='entry-list'),
    path('encode/', EncodePasswordView.as_view(), name='encode'),
    path('decode/', DecodePasswordView.as_view(), name='decode'),
    path('entries/<int:pk>/', DeleteEntryView.as_view(), name='entry-delete'),
]
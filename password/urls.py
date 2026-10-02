from django.urls import path
from .views import (
    VaultEntryListView,
    EncodePasswordView,
    DecodePasswordView,
    DeleteEntryView,
)

urlpatterns = [
    path('entries/', VaultEntryListView.as_view(), name='entry-list'),
    path('encode/', EncodePasswordView.as_view(), name='encode'),
    path('decode/', DecodePasswordView.as_view(), name='decode'),
    path('entries/<int:pk>/', DeleteEntryView.as_view(), name='entry-delete'),
]
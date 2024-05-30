from django.urls import path
from .views import SignUpView, SignInView, MeView

urlpatterns = [
    path('signup/', SignUpView.as_view(), name='signup'),
    path('signin/', SignInView.as_view(), name='signin'),
    path('me/', MeView.as_view(), name='me'),
]
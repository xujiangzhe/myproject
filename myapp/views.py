from django.shortcuts import render

# Create your views here.
import json

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate

User = get_user_model()


class SignUpView(APIView):
    def post(self, request):
        data = {}
        for key in request.data:
            if key:
                for k, v in json.loads(key).items():
                    data[k] = v

        email = data.get('email')
        password = data.get('password')
        if email is None or password is None:
            return Response({'error': 'Please provide both email and password'},
                            status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(email=email).exists():
            return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.create_user(email=email, password=password)
        return Response({'id': user.id, 'email': user.email}, status=status.HTTP_201_CREATED)


class SignInView(APIView):
    def post(self, request):
        data = {}
        for key in request.data:
            if key:
                for k, v in json.loads(key).items():
                    data[k] = v
        email = data.get('email')
        password = data.get('password')
        if email is None or password is None:
            return Response({'error': 'Please provide both email and password'},
                            status=status.HTTP_400_BAD_REQUEST)
        user = authenticate(email=email, password=password)
        if not user:
            return Response({'error': 'Invalid Credentials'}, status=status.HTTP_400_BAD_REQUEST)
        refresh = RefreshToken.for_user(user)
        return Response({'access_token': str(refresh.access_token), 'refresh_token': str(refresh)},
                        status=status.HTTP_200_OK)


class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({'id': user.id, 'email': user.email}, status=status.HTTP_200_OK)

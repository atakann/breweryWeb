from datetime import datetime, timedelta

import jwt
from django.contrib.auth.hashers import make_password, check_password
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from brewerybook import settings
from .models import User

register_body = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    required=['username', 'password'],
    properties={
        'username': openapi.Schema(type=openapi.TYPE_STRING, description='Username for the user'),
        'password': openapi.Schema(type=openapi.TYPE_STRING, description='Password for the user'),
    },
)

login_body = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    required=['username', 'password'],
    properties={
        'username': openapi.Schema(type=openapi.TYPE_STRING, description='Username for the user'),
        'password': openapi.Schema(type=openapi.TYPE_STRING, description='Password for the user'),
    },
)

@swagger_auto_schema(method='post', request_body=register_body)
@api_view(["POST"])
def register(request):
    """
    Register a new user.
    ---
    parameters:
        - name: username
          description: Desired username for the new account.
          required: true
          type: string
          paramType: form
        - name: password
          description: Password for the new account.
          required: true
          type: string
          paramType: form
    responses:
        201:
            description: User created successfully.
        400:
            description: Username already exists or invalid data.
        500:
            description: Internal server error.
    """
    try:
        username = request.data.get("username")
        password = request.data.get("password")

        if not username or not password:
            return Response(
                {"error": "Please provide both username and password"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if User.objects.filter(username=username).exists():
            return Response(
                {"error": "Username already exists"}, status=status.HTTP_400_BAD_REQUEST
            )

        hashed_password = make_password(password)
        user = User(username=username, password=hashed_password)
        user.save()

        return Response(
            {"success": "User created successfully"}, status=status.HTTP_201_CREATED
        )

    except Exception as e:
        return Response(
            {"error": f"An unexpected error occurred: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

@swagger_auto_schema(method='post', request_body=login_body)
@api_view(["POST"])
def login(request):
    """
    Authenticate and obtain JWT for a user.
    ---
    parameters:
        - name: username
          description: Username of the account.
          required: true
          type: string
          paramType: form
        - name: password
          description: Password of the account.
          required: true
          type: string
          paramType: form
    responses:
        200:
            description: Successful authentication, returns a JWT.
        400:
            description: Invalid credentials.
        500:
            description: Internal server error.
    """
    try:
        username = request.data.get("username")
        password = request.data.get("password")

        user = User.objects.get(username=username)

        if not check_password(password, user.password):
            return Response(
                {"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST
            )

        token = jwt.encode(
            {"id": user.id, "exp": datetime.utcnow() + timedelta(hours=1)},
            settings.JWT_SECRET,
            algorithm="HS256",
        )

        return Response({"token": token}, status=status.HTTP_200_OK)

    except User.DoesNotExist:
        return Response(
            {"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return Response(
            {"error": f"An unexpected error occurred: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

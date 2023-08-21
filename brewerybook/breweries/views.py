import requests
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from django.conf import settings
import jwt
from users.models import User
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

breweries_params = [
    openapi.Parameter('by_city', in_=openapi.IN_QUERY, type=openapi.TYPE_STRING, description='Filter breweries by city'),
    openapi.Parameter('by_name', in_=openapi.IN_QUERY, type=openapi.TYPE_STRING, description='Filter breweries by name'),
    openapi.Parameter('by_type', in_=openapi.IN_QUERY, type=openapi.TYPE_STRING, description='Filter breweries by type (e.g., micro, nano)'),
    openapi.Parameter(
        name='Authorization', 
        in_=openapi.IN_HEADER, 
        type=openapi.TYPE_STRING, 
        description='Bearer token for authentication (use like Bearer <token>))',
        required=True
    )
]

def jwt_authenticate(request):
    auth_data = request.headers.get('Authorization')
       
    if not auth_data or ' ' not in auth_data:
        raise AuthenticationFailed("Authorization token not provided")

    prefix, token = auth_data.split(' ')
    if prefix.lower() != "bearer":
        raise AuthenticationFailed("Invalid token prefix")

    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms="HS256")
        user = User.objects.get(id=payload["id"])
        return user
    except jwt.DecodeError:
        raise AuthenticationFailed("Your token is invalid")
    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed("Your token has expired")
    except User.DoesNotExist:
        raise AuthenticationFailed("User not found")

@swagger_auto_schema(method='get', manual_parameters=breweries_params)
@api_view(['GET'])
def breweries(request):
    """
    Get a list of breweries based on query parameters.
    ---
    parameters:
        - name: name
          description: Name of the brewery to search for.
          required: false
          type: string
          paramType: query
        - name: city
          description: City where the brewery is located.
          required: false
          type: string
          paramType: query
        # Add other parameters similarly
    responses:
        200:
            description: A list of breweries matching the query.
    """
    jwt_authenticate(request)

    params = request.GET
    base_url = 'https://api.openbrewerydb.org/breweries'
    
    response = requests.get(base_url, params=params)
    data = response.json()
    
    return Response(data, status=response.status_code)

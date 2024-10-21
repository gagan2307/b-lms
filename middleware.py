# middleware.py
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        id_token = request.cookies.get('__session')
        if id_token:
            request.headers['Authorization'] = f'Bearer {id_token}'
        response = await call_next(request)
        return response


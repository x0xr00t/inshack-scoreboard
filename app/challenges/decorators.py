import base64
from functools import wraps

from django.contrib.auth import authenticate
from django.http import JsonResponse


def staff_member_required_basicauth(view_func):
    """
    Decorator for views that checks that the user is logged in and is a staff member
    """
    @wraps(view_func)
    def wrap(request, *args, **kwargs):
        http_auth = request.META.get('HTTP_AUTHORIZATION')
        if not http_auth:
            return JsonResponse({"message": "Forbidden"}, status=403)

        try:
            auth = http_auth.split(" ")[1].encode()
            uname, passwd = base64.b64decode(auth).decode().split(':')
            user = authenticate(username=uname, password=passwd)
            assert user is not None and user.is_active and user.is_staff
        except Exception:
            return JsonResponse({"message": "Couldn't authenticate you"}, status=403)

        return view_func(request, *args, **kwargs)

    return wrap

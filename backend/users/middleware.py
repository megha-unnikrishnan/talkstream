from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth import get_user_model

User = get_user_model()

class CheckUserStatusMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if request.user.is_authenticated:
            user = User.objects.filter(id=request.user.id).first()
            if user and (not user.is_active or user.is_suspended):
                return JsonResponse({'error': 'Your account is blocked or suspended'}, status=403)

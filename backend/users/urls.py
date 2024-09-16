from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('register/', views.RegisterView.as_view(), name='register'),
    path('users/', views.UserListView.as_view(), name='user_list_create'),
    path('users/<int:pk>/', views.UserDetailView.as_view(), name='user_detail'),
    path('token/', views.CustomTokenObtainPairView.as_view(), name='get_token'),
    path('token/refresh/', TokenRefreshView.as_view(), name='refresh'),
    path('admin/token/', views.AdminTokenObtainPairView.as_view(), name='admin_get_token'),
    path('profile/', views.UserProfileView.as_view(), name='user-profile'),
    path('api/verify-email/<int:user_id>/<str:token>/', views.VerifyEmailView.as_view(), name='verify-email'),
    # path('api/auth/google/', views.GoogleLoginView.as_view(), name='google_login'),
    path('api/auth/google/', views.google_login, name='google_login'),
    path('reset-password-request/', views.PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('reset-password/', views.PasswordResetView.as_view(), name='reset-password'),
    path('change-password/',views.UpdatePasswordView.as_view(),name='change-password'),
    path('user-view/',views.UserViewSet.as_view(),name='user-view'),
    path('users/<int:user_id>/block/', views.block_user, name='block_user'),
    path('users/<int:user_id>/unblock/', views.unblock_user, name='unblock_user'),
]
    




from django.urls import path,include
from . import views
from .views import MyTokenObtainPairView
from django.contrib.auth import views as authview
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.Routes),
    path('token', MyTokenObtainPairView.as_view()),
    path('token/refresh', TokenRefreshView.as_view()),
    path('register', views.Register),
    
    #?BLOGs
    path('blogs/all', views.GetAllBlogs),
    path('blogs/<int:pk>', views.GetBlog),
    path('blogs/add', views.CreateBlog),
    path('blogs/<int:pk>/edit', views.EditBlog),
    path('blogs/<int:pk>/<str:lang>/delete', views.DeleteBlog),

    #?PROFILEs
    path('profile/<int:pk>', views.GetProfile),
    path('profile/<int:pk>/edit', views.EditProfile),
    path('follow', views.FollowSomebody),

    #?INTERESTs
    path('interests', views.GetAllInterests),

    #?AUTHs
    path('change-password', views.ChangePassword),
    path('reset-password-email', views.ResetPasswordMail),
    path('reset-password/<str:code>', views.ResetPassword),
    path('change-email-send', views.ChangeMailSendMail),
    path('change-email/<str:code>', views.ChangeMail),
    path('confirm-email/<str:code>', views.ConfirmMail),


    
]+static(settings.MEDIA_URL,document_root=settings.MEDIA_ROOT)
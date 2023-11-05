from django.urls import path
from django.urls import re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from .import views

schema_view = get_schema_view(
   openapi.Info(
      title="File Management",
      default_version='r1',
      description="for 2 types of users (OWNER / STAFF )",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="contact@snippets.local"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)


urlpatterns = [
    path('', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('owner/registration/', views.OwnerRegistration.as_view(), name='owner_registration'),
    path('staff/registration/', views.StaffRegistration.as_view(), name='staff_registration'),
    path('verify/email/', views.VerifyEmail.as_view(), name='verify_email'),
    path('login/', views.Login.as_view(), name='login'),
    path('logout/', views.UserLogout.as_view(), name='logout'),
    path('forgot/password/', views.ForgotPassword.as_view(), name='forgot_password'),
    path('set/new/password/', views.SetNewPassword.as_view(), name='set_new_password'),
    path('CompanyRegistration',views.CompanyRegistration.as_view()),
    path('AddStaffToCompany',views.AddStaffToCompany.as_view()),
    path('FileUploadAPI',views.FileUploadAPI.as_view()),
    path('fileTransfer/',views.FileTransferAPI.as_view()),
    path('FileListView',views.FileListView.as_view()),
]
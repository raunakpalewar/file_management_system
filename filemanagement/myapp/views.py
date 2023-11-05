from django.shortcuts import render, redirect
from django.http import HttpResponse
import requests
from django.http import HttpResponseRedirect
from decimal import Decimal  # Import Decimal for accurate decimal arithmetic
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializers import *
from .models import *
from django.contrib.auth.hashers import make_password, check_password
import re
from django.contrib.auth import login, logout
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAuthenticatedOrReadOnly, IsAdminUser
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import random
from django.conf import settings
from django.core.mail import send_mail
from datetime import timedelta
from .pagination import CustomPageNumberPagination
from django.db.models import Q
from rest_framework.parsers import MultiPartParser, FormParser



BASE_URL='http://127.0.0.1:8000/'

def generate_otp():
    return str(random.randint(100000, 999999))


def send_otp_email(email, otp):
    subject = 'OTP for user Registration '
    message = f'your otp for Registration is :  {otp}'
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, from_email, recipient_list)


def get_token_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token)
    }


class OwnerRegistration(APIView):
    @swagger_auto_schema(
        operation_description="This if for Customer Registration",
        operation_summary="Customer can Register using this api",
        tags=['OAuth'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING),
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'password': openapi.Schema(type=openapi.TYPE_STRING),
            },
            requried=['email', 'password', 'name']
        ),
    )
    def post(self, request):
        try:
            data = request.data
            try:
                email = data.get('email')
                password = data.get('password')
                name = data.get('name')


                def password_validate(password):
                    if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(){}[\]:;,<>\'\"~])[A-Za-z\d!@#$%^&*(){}[\]:;,<>\'\"~]{8,16}$', password):
                        raise ValueError(
                            "Password must be 8 to 16 characters long with one uppercase, one lowercase, a number, and a special character.")
                email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

                if not email or not re.match(email_regex, email):
                    return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Invalid email format"}, status=status.HTTP_400_BAD_REQUEST)
                if not password:
                    return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Password is required."}, status=status.HTTP_400_BAD_REQUEST)

                try:
                    password_validate(password)
                except Exception as e:
                    return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                otp = generate_otp()
                print(otp)
                send_otp_email(email, otp)
                user_password = make_password(password)
                user = UserRegistration.objects.create(email=email, password=user_password,
                                                       otp=otp, group='owner', full_name=name)
                user.otp_created_at = timezone.now()
                user.user_created_at = timezone.now()
                user.is_registered = True
                user.save()
                return Response({'message': 'user registered successfully'}, status=status.HTTP_201_CREATED)
            except:
                return Response({"status": status.HTTP_400_BAD_REQUEST, 'message': 'could not register user try again'}, status=status.HTTP_400_BAD_REQUEST)
        except:
            return Response({"status": status.HTTP_500_INTERNAL_SERVER_ERROR, 'message': 'could not register user try again'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class StaffRegistration(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="This if for Customer Registration",
        operation_summary="Customer can Register using this api",
        tags=['OAuth'],
         manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER,
                              type=openapi.TYPE_STRING)
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING),
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'password': openapi.Schema(type=openapi.TYPE_STRING),
            },
            requried=['email', 'password', 'name']
        ),
    )
    def post(self, request):
        try:
            data = request.data
            auth_user=request.user
            if auth_user.group=='owner':
                try:
                    email = data.get('email')
                    password = data.get('password')
                    name = data.get('name')


                    def password_validate(password):
                        if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(){}[\]:;,<>\'\"~])[A-Za-z\d!@#$%^&*(){}[\]:;,<>\'\"~]{8,16}$', password):
                            raise ValueError(
                                "Password must be 8 to 16 characters long with one uppercase, one lowercase, a number, and a special character.")
                    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

                    if not email or not re.match(email_regex, email):
                        return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Invalid email format"}, status=status.HTTP_400_BAD_REQUEST)
                    if not password:
                        return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Password is required."}, status=status.HTTP_400_BAD_REQUEST)

                    try:
                        password_validate(password)
                    except Exception as e:
                        return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                    otp = generate_otp()
                    print(otp)
                    send_otp_email(email, otp)
                    user_password = make_password(password)
                    user = UserRegistration.objects.create(email=email, password=user_password,
                                                        otp=otp, group='staff', full_name=name)
                    user.otp_created_at = timezone.now()
                    user.user_created_at = timezone.now()
                    user.is_registered = True
                    user.save()
                    staff_member = Staff.objects.create(name=user, phone_number=data.get('phone_number'), address=data.get('address'))
                    staff_member.save()
                    serializer = UserRegistrationSerializer(user)
                    if serializer.is_valid():
                        serializer.save()
                        return Response({'message': 'user registered successfully'}, status=status.HTTP_201_CREATED)
                    else:
                        return Response({"response":serializer.errors},status.HTTP_400_BAD_REQUEST)
                except Exception as e:
                    return Response({"status": status.HTTP_400_BAD_REQUEST, 'message': f'could not register user try again {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"status":status.HTTP_401_UNAUTHORIZED,"response":"Only owner can register staff"},status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"status": status.HTTP_500_INTERNAL_SERVER_ERROR, 'message': f'could not register user try again {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class VerifyEmail(APIView):
    @swagger_auto_schema(
        operation_description='Verify you email',
        operation_summary='user has to verify his/her email using the otp sended within 3 minutes',
        tags=['OAuth'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING),
                'otp': openapi.Schema(type=openapi.TYPE_NUMBER)
            },
        ),
    )
    def post(self, request):
        data = request.data
        email = data.get('email')
        otp = data.get('otp')

        try:
            user = UserRegistration.objects.get(email=email)
            time_difference = timezone.now()-user.otp_created_at
            if time_difference <= timedelta(minutes=3):
                if otp == user.otp:
                    user.is_valid = True
                    user.is_verified = True
                    user.save()
                    return Response({'status': status.HTTP_200_OK, 'message': "User Verified Successfully"}, status=status.HTTP_200_OK)
                return Response({'status': status.HTTP_400_BAD_REQUEST, "message": "Invalid OTP"}, status.HTTP_400_BAD_REQUEST)
            else:
                otp = generate_otp()
                send_otp_email(email, otp)
                user.otp = otp
                user.otp_created_at = timezone.now()
                user.save()
                return Response({'status': status.HTTP_400_BAD_REQUEST, "message": "time out for  OTP \n new opt sended \n try again using new otp"}, status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status': status.HTTP_404_NOT_FOUND, "message": "User not found"}, status.HTTP_404_NOT_FOUND)


class Login(APIView):
    @swagger_auto_schema(
        operation_description="login here",
        operation_summary='login to you account',
        tags=['OAuth'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email', 'password'],
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING),
                'password': openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
    )
    def post(self, request):
        try:
            data = request.data

            email = data.get('email')
            password = data.get('password')

            email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not email or not re.match(email_regex, email):
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Invalid email format"}, status=status.HTTP_400_BAD_REQUEST)
            if not password:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Password is required."}, status=status.HTTP_400_BAD_REQUEST)

            user = UserRegistration.objects.get(
                email=email, is_verified=True, is_registered=True)

            try:
                if check_password(password, user.password):
                    try:
                        login(request, user)
                        token = get_token_for_user(user)
                        # serializer=UserRegistrationsSerializer(user)
                        return Response({"status": status.HTTP_200_OK, 'message': 'Login successfully', 'token': token, "Your user id": user.id, 'You_are': user.group}, status=status.HTTP_200_OK)
                    except Exception as e:
                        return Response({"messsage": f"user not verified please verify you email first using otp {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({"status": status.HTTP_400_BAD_REQUEST, 'message': "invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({"status": status.HTTP_400_BAD_REQUEST, 'message': 'user not found', 'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"status": status.HTTP_500_INTERNAL_SERVER_ERROR, "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserLogout(APIView):
    def get(self, request):
        logout(request)
        return Response({"status": status.HTTP_200_OK, 'message': 'logout successfully done'}, status.HTTP_200_OK)


class ForgotPassword(APIView):
    @swagger_auto_schema(
        operation_description="Forgot Password",
        operation_summary="Reset Your password using new otp",
        tags=['OAuth'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email'],
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING)
            },
        ),
    )
    def post(self, request):
        try:
            data = request.data
            email = data.get('email')
            email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not email:
                return Response({'message': 'Email id is required.'}, status=status.HTTP_400_BAD_REQUEST)
            if not re.match(email_regex, email):
                return Response({'message': 'Please enter a valid email address.'}, status=status.HTTP_400_BAD_REQUEST)
            try:
                user = UserRegistration.objects.get(email=email)
                otp = generate_otp()
                send_otp_email(email, otp)
                user.otp = otp
                user.otp_created_at = timezone.now()
                user.save()
                return Response({'message': 'OTP sent successfully for password reset.'}, status=status.HTTP_200_OK)

            except UserRegistration.DoesNotExist:
                return Response({'message': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        except UserRegistration.DoesNotExist:
            return Response({'message': 'User not found.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SetNewPassword(APIView):
    @swagger_auto_schema(
        operation_description='Set New Password',
        operation_summary='Please Enter you new password',
        tags=['OAuth'],

        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING),
                'otp': openapi.Schema(type=openapi.TYPE_NUMBER),
                'new_password': openapi.Schema(type=openapi.TYPE_STRING),
                'confirm_password': openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
    )
    def post(self, request):
        try:
            data = request.data
            data['email'] = email
            email = data.get('email')
            otp = data.get('otp')
            password = data.get('new_password')
            cpassword = data.get('confirm_password')

            if not password:
                return Response({"message": "Please enter a new password"}, status=status.HTTP_400_BAD_REQUEST)
            if password != cpassword:
                return Response({"message": "New password and Confirm password must be the same."}, status=status.HTTP_400_BAD_REQUEST)

            password_regex = r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$'
            if not re.match(password_regex, password):
                return Response({"message": "Invalid password format"}, status=status.HTTP_403_FORBIDDEN)

            try:
                user = UserRegistration.objects.get(email=email)
                time_difference = timezone.now()-user.otp_created_at
                if time_difference <= timedelta(minutes=3):
                    if otp == user.otp:
                        user.set_password(password)
                        user.save()
                        return Response({'status': status.HTTP_200_OK, 'message': "Password Changed Successfully"}, status=status.HTTP_200_OK)
                    return Response({'status': status.HTTP_400_BAD_REQUEST, "message": "Invalid OTP"}, status.HTTP_400_BAD_REQUEST)
                else:
                    otp = generate_otp()
                    send_otp_email(email, otp)
                    user.otp = otp
                    user.otp_created_at = timezone.now()
                    user.save()
                    return Response({'status': status.HTTP_400_BAD_REQUEST, "message": "time out for  OTP \n new opt sended \n try again using new otp"}, status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({'status': status.HTTP_404_NOT_FOUND, "message": "User not found"}, status.HTTP_404_NOT_FOUND)
        except:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, "message": "User not found"}, status.HTTP_500_INTERNAL_SERVER_ERROR)



class CompanyRegistration(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="This if for Company Registration",
        operation_summary="Compnay can Register using this api",
        tags=['Company'],
         manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER,
                              type=openapi.TYPE_STRING)
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'company_name': openapi.Schema(type=openapi.TYPE_STRING),
            },
            requried=['company_name'],
        ),
    )
    def post(self, request):
        try:
            auth_user = request.user  # Get the authenticated user
            if auth_user.group == 'owner':
                company_name = request.data.get('company_name')                
                try:
                    # Create the Company object with the actual UserRegistration instance as the company_owner
                    company = Company.objects.create(company_owner=auth_user, company_name=company_name)
                    return Response({"status": status.HTTP_201_CREATED, "message": "Company registered successfully", "company_id": company.id}, status.HTTP_201_CREATED)

                except Exception as e:
                    return Response({"status": status.HTTP_400_BAD_REQUEST, "message": f"{str(e)}"}, status.HTTP_400_BAD_REQUEST)                
            else:
                return Response({"status": status.HTTP_401_UNAUTHORIZED, "message": "Only owner can register a company"}, status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"status": status.HTTP_500_INTERNAL_SERVER_ERROR, "message": f"Could not register company: {str(e)}"}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class AddStaffToCompany(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="This if for Adding Staff to Company",
        operation_summary="Owner can add staff to their company using this API",
        tags=['Company'],
         manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER,
                              type=openapi.TYPE_STRING)
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['email'],
        ),
    )

    def post(self, request):
        try:
            auth_user = request.user  # Get the authenticated user
            if auth_user.group == 'owner':
                staff_member_email = request.data.get('email')
                
                # Check if the company and staff member exist
                try:
                    user=UserRegistration.objects.get(email=staff_member_email)
                    print(user)
                    print(auth_user)
                    company = Company.objects.get(company_owner=auth_user.id)
                    staff_member = Staff.objects.get(name=user.pk)
                except (Company.DoesNotExist, Staff.DoesNotExist):
                    return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Company or staff member does not exist"}, status.HTTP_400_BAD_REQUEST)
                
                # Assign the staff member to the company
                company.staff_member = staff_member
                company.save()
                
                # Return a success response
                return Response({"status": status.HTTP_200_OK, "message": "Staff member added to the company successfully"}, status.HTTP_200_OK)
                
            else:
                return Response({"status": status.HTTP_401_UNAUTHORIZED, "message": "Only owner can add staff to the company"}, status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"status": status.HTTP_500_INTERNAL_SERVER_ERROR, "message": f"Could not add staff to the company: {str(e)}"}, status.HTTP_500_INTERNAL_SERVER_ERROR)

        
class FileUploadAPI(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="This if for File Uploading",
        operation_summary="Staff can Upload Files using this API",
        tags=['Staff'],
         manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER,
                              type=openapi.TYPE_STRING)
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'file': openapi.Schema(type=openapi.TYPE_FILE),
            },
        ),
    )

    def post(self, request):
        try:
            auth_user = request.user

            if auth_user.group == 'staff':
                user=UserRegistration(id=auth_user.pk)
                file_owner=Staff.objects.get(name=user.id)
                
                request.data['file_owner']=file_owner.id
                serializer = FileSerializer(data=request.data)

                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data, status=status.HTTP_201_CREATED)
                else:
                    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"error": "Unauthorized access. Only staff members can upload files."},
                                status=status.HTTP_401_UNAUTHORIZED)

        except Staff.DoesNotExist:
            return Response({"error": "Staff member not found."}, status=status.HTTP_404_NOT_FOUND)
        except Company.DoesNotExist:
            return Response({"error": "Requested company not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": f"Internal server error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class FileTransferAPI(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="This is for transferring files between staff members within the same company.",
        operation_summary="Staff members can transfer files using this API",
        tags=['Staff'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'file': openapi.Schema(type=openapi.TYPE_FILE),
                'receiver_email': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['file', 'receiver_email'],
        ),
    )

    
    def post(self, request):
        try:
            auth_user = request.user
            if auth_user.group == 'staff':
                uploaded_file = request.data.get('file')
                receiver_email = request.data.get('receiver_email')
                
                # Check if the staff members and file exist
                try:
                    recipient_user = UserRegistration.objects.get(id=receiver_email.pk)
                    receiver_name=Staff.objects.get(name=recipient_user.id)
                    
                    file_owner = auth_user.id
                    sender_user=UserRegistration.objects.get(id=auth_user.pk)
                    sender_name=Staff.objects.get(name=sender_user.id)
                    
                    sender_company=Company.objects.get(staff_member=sender_name.pk)
                    
                    print(sender_company)
                    receiver_company=Company.objects.get(staff_member=receiver_name.pk)
                    
                    print(receiver_company)

                    # Create the file object
                    file, created = File.objects.get_or_create(file_owner=sender_name, file=uploaded_file)
                except Exception as e:
                    return Response({"error": f"File, recipient user, or staff member does not exist. {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
                
                # Check if the recipient staff member belongs to the same company as the sender
                if sender_company!=receiver_company:
                    return Response({"error": "Recipient staff member does not belong to the same company."}, status=status.HTTP_400_BAD_REQUEST)
                
                # Transfer the file to the recipient staff member
                file.file_owner = receiver_email
                file.save()
                
                return Response({"message": "File transferred successfully."}, status=status.HTTP_200_OK)
            else:
                return Response({"Message": "Unauthorized access"}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"error": f"Internal server error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    
class FileListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="This is for transferring files between staff members within the same company.",
        operation_summary="Staff members can transfer files using this API",
        tags=['Staff'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
        ],
    )
    def get(self, request):
        try:
            auth_user = request.user
            if auth_user.group=='staff':
                staff=Staff.objects.get(name=auth_user.pk)
                files = File.objects.filter(file_owner=staff.id)
                serializer = FileSerializer(files, many=True)
                return Response({"response":serializer.data}, status=status.HTTP_200_OK)
            else:
                return Response({"response":"unauthorised access"},status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"error": f"Internal server error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

import random
from django.core.mail import send_mail
from django.core.cache import cache
from django.contrib.auth import get_user_model
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from supabase import create_client, Client
from .serializers import ForgotPasswordSerializer, VerifyOTPSerializer, ResetPasswordSerializer
from .models import PasswordChangeHistory

#
User = get_user_model()


supabase: Client = create_client(settings.SUPABASE_URL_1, settings.SUPABASE_KEY)

class ForgotPasswordView(APIView):
    """
    API endpoint to handle forgot password requests.
    Accepts email, checks if it exists, generates OTP, and sends it.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            
            
            response = supabase.table('api_user').select('email').eq('email', email).execute()
            
            if not response.data:
                return Response(
                    {"error": "User does not exist. Please create an account."},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            
            otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
            
            
            print(f"Generated OTP for {email}: {otp}")
            
            
            cache_key = f"otp_{email}"
            cache.set(cache_key, otp, timeout=300)
            
            
            try:
                import textwrap

                def to_bold(text):
                    bold_map = str.maketrans(
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                        "𝐀𝐁𝐂𝐃𝐄𝐅𝐆𝐇𝐈𝐉𝐊𝐋𝐌𝐍𝐎𝐏𝐐𝐑𝐒𝐓𝐔𝐕𝐖𝐗𝐘𝐙"
                        "𝐚𝐛𝐜𝐝𝐞𝐟𝐠𝐡𝐢𝐣𝐤𝐥𝐦𝐧𝐨𝐩𝐪𝐫𝐬𝐭𝐮𝐯𝐰𝐱𝐲𝐳"
                        "𝟎𝟏𝟐𝟑𝟒𝟓𝟔𝟕𝟖𝟗"
                    )
                    return text.translate(bold_map)


                otp_bold = to_bold(str(otp))

                message = textwrap.dedent(f"""\
                Hey 👋,

                We received a request to reset your password.  
                Please use the OTP below to continue:

                👉 Your Password Reset OTP is: {otp_bold}

                ⏰ This code is valid for the next 5 minutes.

                If you didn’t request this, you can safely ignore this email.  

                Stay secure,  
                The XXXX Team 🔒
                """)

                send_mail(
                    subject="XXXX - Password Reset OTP 🔑",
                    message=message,
                    from_email=settings.EMAIL_HOST_USER,
                    recipient_list=[email],
                    fail_silently=False,
                )
                print(f"Email sent to {email} with OTP: {otp}")
            except Exception as e:
                print(f"Failed to send email to {email}: {str(e)}")
                return Response(
                    {"error": f"Failed to send OTP: {str(e)}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            return Response(
                {"message": "OTP sent to your email."},
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.cache import cache
from rest_framework.permissions import AllowAny
from .serializers import VerifyOTPSerializer

class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            reset_token_input = serializer.validated_data['reset_token']
            new_password = serializer.validated_data['new_password']

            cache_key = f"reset_token_{email}"
            stored_token = cache.get(cache_key)

            print(f"Reset - email: {email}, input token: {reset_token_input}, stored token: {stored_token}")

            if not stored_token:
                return Response(
                    {"error": "Reset token has expired or does not exist."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if stored_token != reset_token_input:
                return Response(
                    {"error": "Invalid reset token."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            try:
                user = User.objects.get(email=email)
                old_password_hashed = user.password
                user.set_password(new_password)
                user.save()

                response = supabase.table('api_user').update({
                    'password': user.password
                }).eq('email', email).execute()

                if not response.data:
                    return Response(
                        {"error": "Failed to update password in Supabase."},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )

                PasswordChangeHistory.objects.create(
                    user=user,
                    old_password_hashed=old_password_hashed,
                    new_password_hashed=user.password,
                )

                cache.delete(cache_key)  

                return Response(
                    {"message": "Password reset successfully."},
                    status=status.HTTP_200_OK
                )

            except User.DoesNotExist:
                return Response(
                    {"error": "User does not exist."},
                    status=status.HTTP_404_NOT_FOUND
                )
            except Exception as e:
                return Response(
                    {"error": f"Error resetting password: {str(e)}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        print(f"Reset serializer errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model
from .models import OTP, User, Project, ProjectFile, RequestLog
from .serializers import SignupSerializer, OTPVerificationSerializer, LoginSerializer, UserSerializer
import random
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authtoken.models import Token
from supabase import create_client, Client
import logging
import time
import os

User = get_user_model()
logger = logging.getLogger(__name__)


supabase: Client = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_KEY)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            request.user.auth_token.delete()
            return Response({'message': 'Logged out successfully'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)







class SendMessageView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        subject = request.data.get('subject')
        message = request.data.get('message')
        if not subject or not message:
            return Response({'error': 'Subject and message are required'}, status=status.HTTP_400_BAD_REQUEST)
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=['your_email.a@gmail.com'],
            fail_silently=False,
        )
        return Response({'message': 'Message sent successfully'}, status=status.HTTP_200_OK)



from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from django.utils import timezone
from django.shortcuts import get_object_or_404
from .serializers import ProjectSerializer
from io import BytesIO
import uuid
import logging

class UploadFileView(APIView):
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        logger.debug(f"Request data: {request.data}")
        logger.debug(f"Request files: {request.FILES}")

        try:
            file = request.FILES.get('file')
            if not file:
                logger.error("No file provided")
                return Response({"error": "No file provided"}, status=status.HTTP_400_BAD_REQUEST)

            #
            selected_service = request.data.get('selected_service')
            if not selected_service:
                return Response({"error": "selected_service is required"}, status=status.HTTP_400_BAD_REQUEST)

            valid_services = ["3D Model Design", "3D Printing", "Simulation", "Other"]
            if selected_service not in valid_services:
                return Response({"error": f"Invalid service. Choose one of: {', '.join(valid_services)}"}, status=status.HTTP_400_BAD_REQUEST)

            
            service_description = request.data.get('service_description', '').strip()
            if selected_service == "Other" and not service_description:
                return Response({"error": "service_description is required when selected_service is 'Other'"}, status=status.HTTP_400_BAD_REQUEST)

            
            project_description = request.data.get('project_description', '').strip()

            user_email = request.user.email
            if not user_email:
                return Response({"error": "User email not found"}, status=status.HTTP_400_BAD_REQUEST)

            
            project_id = request.data.get('project_id')
            project_name = request.data.get('project_name')

            
            supabase_client = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_KEY)

            unique_id = str(uuid.uuid4())

            
            main_file_name = f"{user_email}/{unique_id}_{file.name}"
            response = supabase_client.storage.from_(settings.SUPABASE_BUCKET).upload(
                path=main_file_name,
                file=file.read(),
                file_options={"content-type": file.content_type}
            )
            if hasattr(response, 'error') and response.error:
                logger.error(f"Main file upload failed: {response.error}")
                return Response({"error": "Failed to upload main file"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            main_file_url = supabase_client.storage.from_(settings.SUPABASE_BUCKET).get_public_url(main_file_name)

            uploaded_files = [{"file_path": main_file_name, "file_url": main_file_url, "file_name": file.name}]

            
            description_file_url = None
            if project_description:
                txt_content = f"Project Description:\n{project_description}"
                txt_file = BytesIO(txt_content.encode('utf-8'))
                txt_file_name = f"{user_email}/{unique_id}_project_description.txt"

                txt_response = supabase_client.storage.from_(settings.SUPABASE_BUCKET).upload(
                    path=txt_file_name,
                    file=txt_file.read(),
                    file_options={"content-type": "text/plain"}
                )
                if hasattr(txt_response, 'error') and txt_response.error:
                    logger.error(f"Project description txt upload failed: {txt_response.error}")
                    return Response({"error": "Failed to upload project description file"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                description_file_url = supabase_client.storage.from_(settings.SUPABASE_BUCKET).get_public_url(txt_file_name)
                uploaded_files.append({
                    "file_path": txt_file_name,
                    "file_url": description_file_url,
                    "file_name": "project_description.txt"
                })

            
            if selected_service == "Other":
                other_txt_content = f"Service: Other\nCustom Description:\n{service_description}"
                other_txt_file = BytesIO(other_txt_content.encode('utf-8'))
                other_txt_file_name = f"{user_email}/{unique_id}_service_other_description.txt"

                other_txt_response = supabase_client.storage.from_(settings.SUPABASE_BUCKET).upload(
                    path=other_txt_file_name,
                    file=other_txt_file.read(),
                    file_options={"content-type": "text/plain"}
                )
                if hasattr(other_txt_response, 'error') and other_txt_response.error:
                    logger.error(f"Other service txt upload failed: {other_txt_response.error}")
                    return Response({"error": "Failed to upload other service description file"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                other_txt_url = supabase_client.storage.from_(settings.SUPABASE_BUCKET).get_public_url(other_txt_file_name)
                uploaded_files.append({
                    "file_path": other_txt_file_name,
                    "file_url": other_txt_url,
                    "file_name": "service_other_description.txt"
                })

            
            project = None
            if project_name or project_id:
                project, created = Project.objects.get_or_create(
                    id=project_id if project_id else None,
                    defaults={
                        'name': project_name or f"Upload {timezone.now().strftime('%Y-%m-%d')}",
                        'description': project_description or '',
                        'type': selected_service,
                        'status': 'Submitted',
                        'created_at': timezone.now(),
                        'user': request.user,
                        
                    }
                )
                if not created:
                    
                    if project.type != selected_service:
                        project.type = selected_service
                        project.save()

            
            for f in uploaded_files:
                ProjectFile.objects.create(
                    project=project,
                    file_url=f['file_url'],
                    file_name=f['file_name'],
                    uploaded_at=timezone.now(),
                )

            logger.info(f"Files uploaded successfully: {uploaded_files}")
            return Response({
                "message": "Files uploaded successfully",
                "files": uploaded_files,
                "project_id": project.id if project else None,
                "project_name": project.name if project else None,
                "selected_service": selected_service,
                "service_description": service_description if selected_service == "Other" else None
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Upload error: {str(e)}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def list_projects(request):
    projects = Project.objects.filter(user=request.user).order_by('-id')
    data = []
    for p in projects:
        created_at = p.created_at  
        data.append({
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "status": p.status,
            "type": p.type,
            "submittedDate": created_at.isoformat() if created_at else None  
        })
    return Response(data)


@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def project_detail(request, project_id):
    project = get_object_or_404(Project, id=project_id, user=request.user)
    created_at = project.created_at  
    data = {
        "id": project.id,
        "name": project.name,
        "description": project.description,
        "status": project.status,
        "type": project.type,
        "submittedDate": created_at.isoformat() if created_at else None 
    }
    return Response(data)


@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def protected_view(request):
    """
    Endpoint to validate token and return user data.
    Used by the frontend to check authentication status on page load.
    """
    user = request.user
    user_data = {
        "id": user.id,
        "name": user.get_full_name() or user.username,
        "email": user.email,
        "mobile": getattr(user, "mobile", ""), 
        "is_verified": getattr(user, "is_verified", True),  
    }
    return Response({"user": user_data}, status=status.HTTP_200_OK)
from django.contrib.auth import get_user_model

@api_view(['GET'])
def protected_view(request):
    user = request.user
    print(f"User: {user}, Type: {type(user)}, Attributes: {dir(user)}")  
    return Response({
        "name": user.email,  
    })

from uuid import uuid4

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from django.core.cache import cache
from uuid import uuid4
from .serializers import OTPVerificationSerializer  

class VerifyPasswordResetOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = OTPVerificationSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email'].strip().lower()
            otp_input = str(serializer.validated_data['otp']).strip()

            cache_key = f"forgot_otp_{email}"
            cached_otp = cache.get(cache_key)

            print(f"Verify - email: {email}, input OTP: {otp_input}, cached OTP: {cached_otp}")

            if cached_otp is None:
                return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)

            if str(cached_otp) != otp_input:
                return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

            
            reset_token = str(uuid4())
            reset_token_key = f"reset_token_{email}"
            cache.set(reset_token_key, reset_token, timeout=300)  

            print(f"Reset token generated and stored: {reset_token} for email: {email}")

            return Response({
                'message': 'OTP verified successfully',
                'reset_token': reset_token
            }, status=status.HTTP_200_OK)

        print(f"Serializer errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from .models import Notification
from .serializers import NotificationSerializer
from rest_framework.decorators import action
from rest_framework.response import Response

class NotificationViewSet(viewsets.ModelViewSet):
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user)

    @action(detail=True, methods=['patch'])
    def mark_as_read(self, request, pk=None):
        notification = self.get_object()
        notification.is_read = True
        notification.save()
        return Response({'status': 'notification marked as read'})
    


import json
import psycopg2
from django.http import StreamingHttpResponse
from django.conf import settings
import time 

def project_status_stream(request):
    def event_stream():
        
        conn = psycopg2.connect(
            dbname=settings.DATABASES['default']['NAME'],
            user=settings.DATABASES['default']['USER'],
            password=settings.DATABASES['default']['PASSWORD'],
            host=settings.DATABASES['default']['HOST'],
            port=settings.DATABASES['default']['PORT']
        )
        conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        cur = conn.cursor()
        cur.execute("LISTEN project_status_updates;")

        last_heartbeat = time.time()
        heartbeat_interval = 15  

        try:
            while True:
                conn.poll()
                now = time.time()

                
                if now - last_heartbeat >= heartbeat_interval:
                    yield ": heartbeat\n\n"  
                    last_heartbeat = now

                while conn.notifies:
                    notify = conn.notifies.pop(0)
                    yield f"data: {notify.payload}\n\n"
                    last_heartbeat = now  

                
                time.sleep(0.1)

        finally:
            cur.close()
            conn.close()

    response = StreamingHttpResponse(
        event_stream(),
        content_type='text/event-stream'
    )
    response['Cache-Control'] = 'no-cache'
   
    return response



@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def list_projects(request):
    projects = Project.objects.filter(user=request.user).order_by('-id')
    data = []
    for p in projects:
        data.append({
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "status": p.status,
            "submittedDate": p.created_at,
            "type": p.type

        })
    return Response(data)



   
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model
from .models import OTP, User, Project, ProjectFile, RequestLog, TempUser
from .serializers import SignupSerializer, OTPVerificationSerializer, LoginSerializer, UserSerializer
import random
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authtoken.models import Token
from supabase import create_client, Client
import logging
import time
import os
from django.db import transaction
from django.utils.timezone import now, timedelta





from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from django.db import transaction
from .serializers import SignupSerializer
import logging

logger = logging.getLogger(__name__)

class SignupView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        logger.debug(f"Signup request data: {request.data}")

        with transaction.atomic():
            serializer = SignupSerializer(data=request.data)
            if serializer.is_valid():
                temp_user = serializer.save()

                
                subject = "XXXX - Your Verification Code 🔑"

                plain_message = f"""
                    Hey {temp_user.name} 👋,

                    Welcome to XXXX! 💙 We're excited you're here.

                    Your verification code is: {temp_user.otp}

                    ⏰ This code expires in 10 minutes.

                    If you didn't sign up, just ignore this email.

                    Best,
                    The XXXX Team 🚀
                                    """.strip()

                
                html_message = render_to_string('emails/otp_verification.html', {
                    'name': temp_user.name,
                    'otp': temp_user.otp,
                })

                
                msg = EmailMultiAlternatives(
                    subject=subject,
                    body=plain_message,
                    from_email=settings.DEFAULT_FROM_EMAIL or settings.DEFAULT_FROM_EMAIL,
                    to=[temp_user.email]
                )
                msg.attach_alternative(html_message, "text/html")
                msg.send()

                logger.debug(f"OTP email sent to {temp_user.email}: {temp_user.otp}")

                return Response({
                    'message': 'Signup successful. Verification code sent to your email.'
                }, status=status.HTTP_201_CREATED)

            logger.error(f"Signup validation errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyOTPView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        logger.debug(f"Verifying OTP with data: {request.data}")
        serializer = OTPVerificationSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email'].lower()
            otp = serializer.validated_data['otp']
            try:
                temp_user = TempUser.objects.get(email__iexact=email, otp=otp)
                if temp_user.created_at < now() - timedelta(minutes=10):
                    temp_user.delete()
                    logger.error(f"OTP expired for email: {email}")
                    return Response({'error': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)
                
                with transaction.atomic():
                    user = User.objects.create_user(
                        email=temp_user.email,
                        name=temp_user.name,
                        mobile=temp_user.mobile,
                        password=temp_user.raw_password,  
                        is_verified=True,
                        is_active=True
                    )
                    token = Token.objects.create(user=user)
                    temp_user.delete()
                    logger.debug(f"User created and TempUser deleted for email: {email}")
                    return Response({
                        'message': 'OTP verified successfully',
                        'token': token.key,
                        'user': UserSerializer(user).data
                    }, status=status.HTTP_200_OK)
            except TempUser.DoesNotExist:
                logger.error(f"Invalid OTP or email: {email}")
                return Response({'error': 'Invalid OTP or email'}, status=status.HTTP_400_BAD_REQUEST)
        logger.error(f"OTP verification failed: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        logger.debug(f"Login request data: {request.data}")
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            logger.info(f"User authenticated: {user.email}")
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                'token': token.key,
                'user': {
                    'id': str(user.id),
                    'email': user.email,
                    'name': user.name,
                    'mobile': user.mobile,
                    'is_verified': user.is_verified
                }
            }, status=status.HTTP_200_OK)
        logger.error(f"Login failed: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

import random
from django.core.mail import send_mail
from django.core.cache import cache
from django.contrib.auth import get_user_model
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from supabase import create_client, Client
from .serializers import ForgotPasswordSerializer, VerifyOTPSerializer, ResetPasswordSerializer
from .models import PasswordChangeHistory


User = get_user_model()


supabase: Client = create_client(settings.SUPABASE_URL_1, settings.SUPABASE_KEY)

from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings
from django.core.cache import cache
from django.db import transaction
import random
import logging

logger = logging.getLogger(__name__)

from .serializers import ForgotPasswordSerializer

class ForgotPasswordView(APIView):
    """
    API endpoint to handle forgot password requests.
    Accepts email, checks if it exists, generates OTP, and sends beautiful HTML email.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']

        
            response = supabase.table('api_user').select('email').eq('email', email).execute()
            
            if not response.data:
                return Response(
                    {"error": "User does not exist. Please create an account."},
                    status=status.HTTP_404_NOT_FOUND
                )

            
            otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])

            
            cache_key = f"forgot_otp_{email}"
            cache.set(cache_key, otp, timeout=300)  

            logger.debug(f"Password reset OTP generated for {email}: {otp}")

            
            plain_message = f"""
Hey 👋,

We received a request to reset your XXXX password.

Your verification code is: {otp}

⏰ This code expires in 5 minutes.

If you didn't request this, please ignore this email.

Stay safe,
The XXXX Team 🔒
            """.strip()

           
            html_message = render_to_string('emails/password_reset_otp.html', {
                'otp': otp,
                'email': email,
            })

            
            try:
                msg = EmailMultiAlternatives(
                    subject="XXXX - Password Reset Code 🔑",
                    body=plain_message,
                    from_email=settings.DEFAULT_FROM_EMAIL or settings.DEFAULT_FROM_EMAIL,
                    to=[email]
                )
                msg.attach_alternative(html_message, "text/html")
                msg.send()

                logger.info(f"Password reset OTP email sent to {email}")
            except Exception as e:
                logger.error(f"Failed to send password reset email to {email}: {str(e)}")
                return Response(
                    {"error": "Failed to send OTP email. Please try again later."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            return Response(
                {"message": "Password reset code sent to your email."},
                status=status.HTTP_200_OK
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .models import UserFeedback
from .serializers import UserFeedbackSerializer


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .models import UserFeedback
from .serializers import UserFeedbackSerializer


from .serializers import UserFeedbackCreateSerializer

class SubmitFeedbackView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        data = {
            'project': request.data.get('project'),  
            'rating': request.data.get('rating'),
            'feedback_text': request.data.get('feedback_text'),
            'emojis': request.data.get('emojis'),
        }
        serializer = UserFeedbackCreateSerializer(data=data)  
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response({"message": "Feedback submitted successfully!"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class FeedbackListView(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        feedbacks = UserFeedback.objects.select_related('user', 'project').filter(is_approved=True)
        serializer = UserFeedbackSerializer(feedbacks, many=True)
        return Response(serializer.data)
    

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from .models import FeedbackDetail
from .serializers import FeedbackDetailSerializer

class FeedbackDetailListView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        feedback_details = FeedbackDetail.objects.all()
        serializer = FeedbackDetailSerializer(feedback_details, many=True)
        return Response(serializer.data)



from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from .models import UserFeedback
from .serializers import UserFeedbackSerializer  

@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def user_feedback_list(request):
    """
    Fetch all feedback submitted by the authenticated user
    Shows: project_name, short_note, rating, emojis, feedback_text, status, popup_count
    """
    feedbacks = UserFeedback.objects.filter(user=request.user).order_by('-created_at')
    serializer = UserFeedbackSerializer(feedbacks, many=True)
    return Response(serializer.data)

@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def increment_feedback_popup(request, feedback_id):
    """
    Increment popup_count for approved feedback (max 3)
    """
    feedback = get_object_or_404(UserFeedback, id=feedback_id, user=request.user)

    if feedback.status != 'approved':
        return Response({"error": "Only approved feedback can have popups expanded"}, status=400)

    if feedback.popup_count >= 3:
        return Response({"error": "Maximum popup expansions reached (3)"}, status=400)

    feedback.popup_count += 1
    feedback.save()

    return Response({
        "message": "Popup count incremented",
        "new_count": feedback.popup_count
    }, status=200)

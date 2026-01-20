from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from api.models import User, ProjectFile, UserFeedback
from api.email_backends import SignalEmailBackend


user_feedback_previous_state = {}

@receiver(post_save, sender=User)
def send_user_creation_emails(sender, instance, created, **kwargs):
    """
    Signal to send welcome email to user and notification to admin upon user creation.
    """
    print(f"User creation signal triggered for {instance.email}, created: {created}")
    if created and instance.is_active:
        subject = "Welcome to Our Platform!"
        html_message = render_to_string('emails/welcome_email.html', {
            'name': instance.name,
        })
        plain_message = strip_tags(html_message)
        print(f"Sending welcome email to {instance.email} from {settings.SIGNAL_DEFAULT_FROM_EMAIL}")
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.SIGNAL_DEFAULT_FROM_EMAIL,
            recipient_list=[instance.email],
            html_message=html_message,
            fail_silently=False,
            connection=SignalEmailBackend(),
        )

        admin_emails = [user.email for user in User.objects.filter(is_staff=True)]
        if admin_emails:
            print(f"Sending admin notification to {admin_emails} from {settings.SIGNAL_DEFAULT_FROM_EMAIL}")
            subject = "New User Registration"
            html_message = render_to_string('emails/admin_user_creation.html', {
                'name': instance.name,
                'email': instance.email,
                'mobile': instance.mobile,
            })
            plain_message = strip_tags(html_message)
            send_mail(
                subject=subject,
                message=plain_message,
                from_email=settings.SIGNAL_DEFAULT_FROM_EMAIL,
                recipient_list=admin_emails,
                html_message=html_message,
                fail_silently=False,
                connection=SignalEmailBackend(),
            )

@receiver(post_save, sender=ProjectFile)
def send_project_upload_notification(sender, instance, created, **kwargs):
    """
    Signal to send email to admin when a project file is uploaded, including all project files.
    """
    print(f"Project file signal triggered for file: {instance.file_name}, created: {created}")
    if created:
        project = instance.project
        user = project.user
        
        project_files = project.files.all()
        admin_emails = [user.email for user in User.objects.filter(is_staff=True)]
        if admin_emails:
            print(f"Sending project upload notification to {admin_emails} from {settings.SIGNAL_DEFAULT_FROM_EMAIL}")
            subject = "New Project File(s) Uploaded"
            html_message = render_to_string('emails/admin_project_upload.html', {
                'username': user.name,
                'email': user.email,
                'mobile': user.mobile,
                'project_name': project.name,
                'project_files': project_files, 
            })
            plain_message = strip_tags(html_message)
            send_mail(
                subject=subject,
                message=plain_message,
                from_email=settings.SIGNAL_DEFAULT_FROM_EMAIL,
                recipient_list=admin_emails,
                html_message=html_message,
                fail_silently=False,
                connection=SignalEmailBackend(),
            )

@receiver(post_save, sender=UserFeedback)
def send_feedback_notification(sender, instance, created, **kwargs):
    """
    Signal to send email to admin when feedback is submitted.
    """
    print(f"Feedback signal triggered for user: {instance.user.email}, created: {created}")
    if created:
        user = instance.user
        admin_emails = [user.email for user in User.objects.filter(is_staff=True)]
        if admin_emails:
            print(f"Sending feedback notification to {admin_emails} from {settings.SIGNAL_DEFAULT_FROM_EMAIL}")
            subject = "New Feedback Submitted"
            html_message = render_to_string('emails/admin_feedback.html', {
                'name': user.name,
                'email': user.email,
                'feedback_text': instance.feedback_text,
                'rating': instance.rating or 'Not provided',
                'emojis': instance.emojis or 'None',
                'project_name': instance.project.name,
            })
            plain_message = strip_tags(html_message)
            send_mail(
                subject=subject,
                message=plain_message,
                from_email=settings.SIGNAL_DEFAULT_FROM_EMAIL,
                recipient_list=admin_emails,
                html_message=html_message,
                fail_silently=False,
                connection=SignalEmailBackend(),

            )

@receiver(post_save, sender=UserFeedback)
def send_feedback_approved_notification(sender, instance, created, **kwargs):
    """
    Signal to send email to user when their feedback is approved.
    """
    if not created:  
        previous_is_approved = user_feedback_previous_state.get(instance.id, False)
        print(f"Feedback approval signal triggered for user: {instance.user.email}, is_approved: {instance.is_approved}, previous: {previous_is_approved}")
        if instance.is_approved and not previous_is_approved:
            subject = "Your Feedback Has Been Approved!"
            html_message = render_to_string('emails/feedback_approved.html', {
                'name': instance.user.name,
                'project_name': instance.project.name,
                'feedback_text': instance.feedback_text,
                'rating': instance.rating or 'Not provided',
                'emojis': instance.emojis or 'None',
                'homepage_url': settings.HOMEPAGE_URL,  
            })
            plain_message = strip_tags(html_message)
            print(f"Sending feedback approved email to {instance.user.email} from {settings.SIGNAL_DEFAULT_FROM_EMAIL}")
            send_mail(
                subject=subject,
                message=plain_message,
                from_email=settings.SIGNAL_DEFAULT_FROM_EMAIL,
                recipient_list=[instance.user.email],
                html_message=html_message,
                fail_silently=False,
                connection=SignalEmailBackend(),
            )


from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, OTP, Project, ProjectFile, RequestLog
from django.utils.html import format_html
from django.contrib import messages
from .models import Notification


class ProjectFileInline(admin.TabularInline):
    model = ProjectFile
    extra = 0
    fields = ('file_name', 'file_url', 'uploaded_at', 'file_link')
    readonly_fields = ('uploaded_at', 'file_link')

    def file_link(self, obj):
        return format_html('<a href="{}" target="_blank">View File</a>', obj.file_url)
    file_link.short_description = 'File URL'


class UserAdmin(BaseUserAdmin):
    model = User
    list_display = ('email', 'name', 'mobile', 'is_verified', 'is_active', 'is_staff', 'is_superuser', 'project_count', 'upload_count')
    list_filter = ('is_verified', 'is_active', 'is_staff', 'is_superuser')
    search_fields = ('email', 'name', 'mobile')
    ordering = ('email',)
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('name', 'mobile')}),
        ('Permissions', {'fields': ('is_active', 'is_verified', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'name', 'mobile', 'password1', 'password2', 'is_verified', 'is_staff', 'is_superuser'),
        }),
    )

    def project_count(self, obj):
        return obj.project_set.count()
    project_count.short_description = 'Projects'

    def upload_count(self, obj):
        return RequestLog.objects.filter(user=obj, endpoint='/api/upload-file/', success=True).count()
    upload_count.short_description = 'Uploads'


class ProjectAdmin(admin.ModelAdmin):
    list_display = ('name', 'user_email', 'status', 'type', 'description', 'file_count', 'created_at')
    list_filter = ('status', 'type', 'user')
    search_fields = ('name', 'description', 'user__email')
    inlines = [ProjectFileInline]
    list_editable = ('status', 'description')
    actions = ['mark_completed', 'mark_in_progress']

    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User'

    def file_count(self, obj):
        return obj.files.count()
    file_count.short_description = 'Files'

    def mark_completed(self, request, queryset):
        queryset.update(status='Completed')
        self.message_user(request, "Selected projects marked as Completed", messages.SUCCESS)
    mark_completed.short_description = "Mark as Completed"

    def mark_in_progress(self, request, queryset):
        queryset.update(status='In Progress')
        self.message_user(request, "Selected projects marked as In Progress", messages.SUCCESS)
    mark_in_progress.short_description = "Mark as In Progress"


class ProjectFileAdmin(admin.ModelAdmin):
    list_display = ('file_name', 'project_name', 'user_email', 'file_url', 'file_link', 'uploaded_at')
    list_filter = ('project__user', 'project__status')
    search_fields = ('file_name', 'project__name', 'project__user__email')
    readonly_fields = ('uploaded_at', 'file_link')

    def project_name(self, obj):
        return obj.project.name
    project_name.short_description = 'Project'

    def user_email(self, obj):
        return obj.project.user.email
    user_email.short_description = 'User'

    def file_link(self, obj):
        return format_html('<a href="{}" target="_blank">View File</a>', obj.file_url)
    file_link.short_description = 'File URL'


class RequestLogAdmin(admin.ModelAdmin):
    list_display = ('user_email', 'endpoint', 'status_code', 'success', 'response_time', 'timestamp')
    list_filter = ('endpoint', 'success', 'status_code', 'user')
    search_fields = ('user__email', 'endpoint')
    readonly_fields = ('timestamp',)

    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User'



@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ("id", "subject", "created_at")
    search_fields = ("subject", "message")


from django.contrib import admin
from .models import PasswordChangeHistory

@admin.register(PasswordChangeHistory)
class PasswordChangeHistoryAdmin(admin.ModelAdmin):
    """
    Admin interface for PasswordChangeHistory model.
    Displays user, old/new hashed passwords, and timestamp.
    """
    list_display = ('user', 'old_password_hashed', 'new_password_hashed', 'changed_at')
    list_filter = ('changed_at', 'user')
    search_fields = ('user__username',)
    readonly_fields = ('changed_at',)

from django.contrib import admin
from .models import UserFeedback


@admin.register(UserFeedback)
class UserFeedbackAdmin(admin.ModelAdmin):
    list_display = (
        'user_email', 'user_name', 'project_name', 'rating', 'emojis',
        'feedback_text_short', 'status', 'short_note', 'popup_count', 'created_at', 'is_approved'
    )
    list_filter = ('status', 'is_approved', 'created_at')
    search_fields = ('feedback_text', 'user__name', 'user__email', 'project__name')
    list_editable = ('status', 'short_note', 'popup_count', 'is_approved')
    readonly_fields = ('created_at', 'user_email', 'user_name', 'project_name')

    def user_email(self, obj):
        return obj.user.email if obj.user else 'No User'
    user_email.short_description = 'Email'

    def user_name(self, obj):
        return obj.user.name if obj.user and obj.user.name else 'Unnamed'
    user_name.short_description = 'Name'

    def project_name(self, obj):
        return obj.project.name if obj.project else 'No Project'
    project_name.short_description = 'Project'

    def feedback_text_short(self, obj):
        return obj.feedback_text[:50] + '...' if len(obj.feedback_text) > 50 else obj.feedback_text
    feedback_text_short.short_description = 'Feedback (short)'

    actions = ['approve_selected', 'reject_selected']

    def approve_selected(self, request, queryset):
        queryset.update(status='approved', is_approved=True)
        self.message_user(request, "Selected feedback approved", messages.SUCCESS)
    approve_selected.short_description = "Approve selected"

    def reject_selected(self, request, queryset):
        queryset.update(status='rejected', is_approved=False)
        self.message_user(request, "Selected feedback rejected", messages.SUCCESS)
    reject_selected.short_description = "Reject selected"


from django.contrib import admin
from django.contrib.auth import get_user_model
from django import forms
from django.shortcuts import render, redirect
from django.contrib import messages
from django.conf import settings
from django.core.mail import EmailMultiAlternatives, get_connection
from django.template import Template, Context
from .models import EmailLog, Project  

User = get_user_model()

class SendEmailForm(forms.Form):
    subject = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={
            'class': 'vLargeTextField',
            'placeholder': 'e.g., Update for {{ name }} - {{ project_name }}'
        })
    )
    
    project_name = forms.CharField(
        max_length=200,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'vLargeTextField',
            'placeholder': 'e.g., 5 or Skyline Tower Project'
        }),
        help_text="Enter Project ID (number) to auto-fetch name, or type name directly. Use {{ project_name }} in messages.",
    )
    
    message = forms.CharField(
        widget=forms.Textarea(attrs={
            'rows': 8,
            'class': 'vLargeTextField',
            'placeholder': 'Plain text message (optional if HTML is used)'
        }),
        required=False,
        help_text="Plain text version. Placeholders: {{ name }}, {{ email }}, {{ mobile }}, {{ project_name }}"
    )
    
    html_message = forms.CharField(
        widget=forms.Textarea(attrs={
            'rows': 15,
            'class': 'vLargeTextField',
            'placeholder': '<h2>Hello {{ name }}</h2><p>Update for {{ project_name }}...</p>'
        }),
        required=False,
        help_text="HTML version. Same placeholders work."
    )

    def clean(self):
        cleaned_data = super().clean()
        message = cleaned_data.get('message')
        html_message = cleaned_data.get('html_message')

        if not message and not html_message:
            raise forms.ValidationError(
                "You must provide either a plain text message or an HTML message (or both)."
            )
        return cleaned_data


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('email', 'name', 'mobile', 'is_verified')
    search_fields = ('email', 'name')
    actions = ['send_custom_email']

    def send_custom_email(self, request, queryset):
        if 'apply' in request.POST:
            form = SendEmailForm(request.POST)
            if form.is_valid():
                subject = form.cleaned_data['subject']
                plain_message = form.cleaned_data['message']
                html_message = form.cleaned_data['html_message']
                project_input = form.cleaned_data.get('project_name', '').strip()

                messages_to_send = []
                valid_users = []

                for user in queryset:
                    if not user.email:
                        continue

                    
                    project_name_to_use = "Your Project" 

                    if project_input:
                        if project_input.isdigit():
                            try:
                                proj = Project.objects.get(id=int(project_input))
                                project_name_to_use = proj.name or f"Project #{proj.id}"
                            except Project.DoesNotExist:
                                project_name_to_use = f"Unknown Project (ID: {project_input})"
                        else:
                            project_name_to_use = project_input

                    context = Context({
                        'name': user.name or user.email.split('@')[0] or 'User',
                        'email': user.email,
                        'mobile': user.mobile or 'N/A',
                        'project_name': project_name_to_use,
                    })

                    rendered_subject = Template(subject).render(context)
                    rendered_plain = Template(plain_message).render(context) if plain_message else ""
                    rendered_html = Template(html_message).render(context) if html_message else None

                    msg = EmailMultiAlternatives(
                        subject=rendered_subject,
                        body=rendered_plain or " ",
                        from_email=settings.SIGNAL_DEFAULT_FROM_EMAIL,
                        to=[user.email],
                    )

                    if rendered_html:
                        msg.attach_alternative(rendered_html, "text/html")

                    messages_to_send.append(msg)
                    valid_users.append(user)

                if messages_to_send:
                    connection = get_connection(
                        backend='django.core.mail.backends.smtp.EmailBackend',
                        host=settings.SIGNAL_EMAIL_HOST,
                        port=settings.SIGNAL_EMAIL_PORT,
                        username=settings.SIGNAL_EMAIL_HOST_USER,
                        password=settings.SIGNAL_EMAIL_HOST_PASSWORD,
                        use_tls=settings.SIGNAL_EMAIL_USE_TLS,
                        fail_silently=False,
                    )

                    try:
                        connection.open()
                        connection.send_messages(messages_to_send)
                        connection.close()

                        logs = []
                        for user, msg in zip(valid_users, messages_to_send):
                            logs.append(EmailLog(
                                recipient=user,
                                subject=msg.subject,
                                message=msg.body,
                                html_message=msg.alternatives[0][0] if msg.alternatives else None,
                                success=True
                            ))
                        EmailLog.objects.bulk_create(logs)

                        messages.success(request, f"Successfully sent {len(messages_to_send)} email(s)!")

                    except Exception as e:
                        logs = []
                        for user in valid_users:
                            logs.append(EmailLog(
                                recipient=user,
                                subject=subject,
                                message=plain_message or "[HTML only]",
                                html_message=html_message,
                                success=False,
                                error_message=str(e)[:500]
                            ))
                        EmailLog.objects.bulk_create(logs)

                        messages.error(request, f"Failed to send emails: {str(e)}")

                else:
                    messages.warning(request, "No valid email addresses found in selected users.")

                return redirect('admin:api_user_changelist')

        form = SendEmailForm()
        return render(request, 'admin/send_custom_email.html', {
            'title': 'Send Custom Email (HTML or Plain Text)',
            'form': form,
            'users': queryset,
            'selected_count': queryset.count(),
        })

    send_custom_email.short_description = "Send custom email"


@admin.register(EmailLog)
class EmailLogAdmin(admin.ModelAdmin):
    list_display = ('recipient', 'subject', 'sent_at', 'success')
    list_filter = ('success', 'sent_at')
    search_fields = ('recipient__email', 'subject')
    readonly_fields = ('sent_at',)
    date_hierarchy = 'sent_at'



admin.site.register(OTP)
admin.site.register(Project, ProjectAdmin)
admin.site.register(ProjectFile, ProjectFileAdmin)
admin.site.register(RequestLog, RequestLogAdmin)


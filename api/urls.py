from django.urls import path
from . import views
from .views import SignupView, VerifyOTPView, LoginView, LogoutView, SendMessageView, UploadFileView, list_projects, ForgotPasswordView, ResetPasswordView, SubmitFeedbackView, FeedbackListView, FeedbackDetailListView, VerifyPasswordResetOTPView, user_feedback_list, increment_feedback_popup


urlpatterns = [
    path('signup/', SignupView.as_view(), name='signup'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('send-message/', SendMessageView.as_view(), name='send-message'),
    path('upload-file/', UploadFileView.as_view(), name='upload-file'),
    path('projects/', views.list_projects, name='list-projects'),
    path('projects/<int:project_id>/', views.project_detail, name='project-detail'),
    path('protected/', views.protected_view, name='protected'),
    path('verify-reset-otp/', VerifyPasswordResetOTPView.as_view(), name='verify-reset-otp'),
    path('api/projects/<int:projectId>/', views.project_detail, name='project_detail'),
    path('project-status-stream/', views.project_status_stream, name='project_status_stream'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    path('submit-feedback/', views.SubmitFeedbackView.as_view(), name='submit-feedback'),
    path('feedback/', views.FeedbackListView.as_view(), name='feedback-list'),
    path('feedback-details/', views.FeedbackDetailListView.as_view(), name='feedback-details'),
    path('user-feedback/', user_feedback_list, name='user-feedback-list'),
    path('feedback/<int:feedback_id>/increment-popup/', increment_feedback_popup, name='increment-feedback-popup')
    
]


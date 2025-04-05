from celery import shared_task

from django.core.mail import send_mail
from django.conf import settings



@shared_task(bind=True)
def send_otp_email(self, email, otp_code):
    """Generate a 6-digit OTP and send asynchronously."""
    subject = 'Your OTP Code'
    message = f'Your OTP Code is: {otp_code}'
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [email]
    
    send_mail(
        subject,
        message,
        from_email,
        recipient_list,
        fail_silently=False
    )
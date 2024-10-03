from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMultiAlternatives
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.urls import reverse_lazy, reverse
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

from conf import settings
from users.token import email_verification_token
from users.form import RegistrationForm, LoginForm


# Create your views here.
def just_page_view(request):
    return render(request, 'registration/just-page.html')


def verify_email(request, uidb64, token):
    uid = force_str(urlsafe_base64_decode(uidb64))
    user = User.objects.get(pk=uid)
    if user is not None and email_verification_token.check_token(user, token):
        user.is_active = True
        user.save()
        return redirect(reverse_lazy('users:login'))
    else:
        return render(request, 'registration/email_not_verified.html')


def send_email_verification(request, user):
    token = email_verification_token.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    current_site = get_current_site(request)
    verification_url = reverse('users:verify-email', kwargs={'uidb64': uid, 'token': token})
    full_url = f"http://{current_site.domain}/verify-email/{uid}/{token}"

    text_content = render_to_string(
        'registration/verify-email.html',
        {'user': user, 'full_url': full_url}
    )

    message = EmailMultiAlternatives(
        subject='Verification email',
        body=text_content,
        to=[user.email],
        from_email=settings.EMAIL_HOST_USER,
    )
    message.attach_alternative(text_content, 'text/html')
    message.send()


def register_view(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(raw_password=form.cleaned_data['password1'])
            user.is_active = False
            user.save()
            # verify email
            send_email_verification(request, user)
            return redirect(reverse_lazy('users:login'))
        else:
            print(form.is_valid())
            errors = form.errors
            return render(request, 'registration/user-register.html', {'errors': errors})
    else:
        return render(request, 'registration/user-register.html')


def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = authenticate(request=request, email=email, password=password)
            if user is not None:
                login(request, user)
                return redirect('users:just_page')
            else:
                # message should be here
                # errors = form.errors
                return render(request, 'registration/user-login.html')
    else:
        return render(request, 'registration/user-login.html')


def logout_view(request):
    return HttpResponse("for logout")

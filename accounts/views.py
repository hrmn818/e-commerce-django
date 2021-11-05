from django.http.response import HttpResponse
from django.shortcuts import render,redirect
from django.utils import http
import accounts
from accounts.models import Account
from accounts.forms import RegistrationForm
from .models import Account
from django.contrib import messages,auth
from django.contrib.auth.decorators import login_required 
# Create your views here.
#verification mail
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage, message
def register(request):
    if request.method=='POST':
        form=RegistrationForm(request.POST)
        if form.is_valid():
            first_name=form.cleaned_data['first_name']
            last_name=form.cleaned_data['last_name']
            phone_number=form.cleaned_data['phone_number']
            email=form.cleaned_data['email']
            password=form.cleaned_data['password']
            username=email.split("@")[0]
            user=Account.objects.create_user(first_name=first_name,last_name=last_name,email=email,username=username,password=password)
            user.phone_number =phone_number
            user.save()
            #user activation
            current_site=get_current_site(request)
            mail_subject="please activate your account."
            message= render_to_string('account/account_verification_mail.html',{
                'user':user,
                'domain': current_site,
                'uid':urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            }
            )
            to_email=email
            send_email =EmailMessage(mail_subject,message,to=[to_email])
            send_email.send()
            #messages.success(request,'Thank you for registring with us.we sent a verification email to your email address.please verify.')
            return redirect('/accounts/login/?command=verification&email='+email)
    else:
        form=RegistrationForm()
    context={
        'form':form,
    }
    return render (request,'accounts/register.html',context)

def login(request):
    if request.method=='POST':
        email= request.POST['email']
        password = request.POST['password']

        user=auth.authenticate(email=email,password=password)
        if user is not None:
            auth.login(request,user)
            messages.success(request,"you are now logged in.")
            return redirect('home')
        else:
            messages.error(request,"invalid login credentials")
            return redirect("login")
    return render (request,'accounts/login.html')

@login_required(login_url='login')
def logout(request):
    auth.logout(request)
    messages.success(request,"your are logged out")

    return redirect('login')

def activate(request,uidb64,token):
    try:
        uid=urlsafe_base64_decode(uidb64).decode()
        user=Account._default_manager.get(pk=uid)
    except(TypeError,ValueError,OverflowError,Account.DoesNotExist):
        user=None
    
    if user is not None and default_token_generator.check_token(user,token):
        user.is_active = True
        user.save
        messages.success(request,'congratulations your account is activated.')
        return redirect('login')
    else:
        messages.ERROR(request,'invalid activation link')
        return redirect('register')
    
@login_required(login_url='login')
def dashboard(request):
    return render(request,'accounts/dashboard.html')

def forgotpassword(request):
    if request.method=='POST':
        email= request.POST['email']
        if Account.objects.filter(email=email).exsist():
            user =Account.objects.get(email__iexact=email)
            # Reset Password Email
            current_site=get_current_site(request)
            mail_subject="Reset your password "
            message= render_to_string('account/ ',{
                'user':user,
                'domain': current_site,
                'uid':urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            }
            )
            to_email=email
            send_email =EmailMessage(mail_subject,message,to=[to_email])
            send_email.send()

            messages.success(request,"password reset email has been sent to your email address.")
            return redirect('login')
        else:
            messages.error(request,'account don\'t exsist')
            return redirect('forgotpassword')
        
        return render(request,'accounts/forgotpassword.html')

def resetpassword_validate(request,uidb64,token):
    try:
        uid=urlsafe_base64_decode(uidb64).decode()
        user=Account._default_manager.get(pk=uid)
    except(TypeError,ValueError,OverflowError,Account.DoesNotExist):
        user=None
    
    if user is not None and default_token_generator.check_token(user,token):
        request.session['uid'] = uid
        messages.success(request,'plese reset your password')
        return redirect('resetPassword')

    else:
        messages.error(request,'this link is expired')
        return redirect('login')

def resetPassword(request):
    if request.method=='POST':
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if password==confirm_password:
            uid= request.session.get('uid')
            user = Account.objects.get(pk=uid)
            user.set_password(password)
            user.save()
            messages.success(request,"password reset succesfully")
            return redirect('login')
        else:
            messages.error(request,"password do not match")
            return redirect('resetPassword')
    else:
        return render(request,'accounts/resetPassword.html')
from rest_framework.response import Response
from rest_framework.decorators import api_view,permission_classes
from django.contrib.auth.models import User
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from .models import *
from rest_framework.permissions import IsAuthenticated
from .serializers import *
from django.utils.text import slugify
from django.contrib.auth.hashers import make_password
from rest_framework import generics
from django.contrib.auth import authenticate
from django.core.mail import send_mail
import jwt
import tensorflow as tf
from django.db.models import Q
import difflib
from django.conf import settings
from django.core.files.storage import default_storage
from django.shortcuts import render
from keras.applications import vgg16
from keras.applications.imagenet_utils import decode_predictions
from keras.utils.image_utils import img_to_array,load_img
from tensorflow.python.keras.backend import set_session
from datetime import datetime,timezone,timedelta

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['profile'] = ProfileSerializer(Profile.objects.get(user=user)).data


        return token

class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer

@api_view(['GET'])
def Routes(request):
    routes = [
        '/api/token/',
        '/api/token/refresh/',
        '/api/register/',
        '/api/blogs/all',
        '/api/blogs/add',
        '/api/blogs/<int:pk>',
        '/api/blogs/<int:pk>/edit',
        '/api/blogs/<int:pk>/delete',
    ]

    return Response(routes)

#TODO Register a user
@api_view(['POST'])
def Register(request):
    if request.data.get('username') is None:
        return Response({"msg":"Username is not provided 😅"},status=400)
    
    if request.data.get('email') is None:
        return Response({"msg":"Email is not provided 😅"},status=400)
    
    if request.data.get('password') is None:
        return Response({"msg":"Password 1 is not provided 😅"},status=400)
    
    if request.data.get('password1') is None:
        return Response({"msg":"Password 2 is not provided 😅"},status=400)
    
    if len(User.objects.filter(username=request.data['username']))>0:
        return Response({"msg":"This username taken 😥"},status=400)
    
    if len(User.objects.filter(email=request.data['email']))>0:
        return Response({"msg":"This email taken 😥"},status=400)
    
    if request.data.get('password1')!=request.data.get('password'):
        return Response({"msg":"Passwords do not match 😒"},status=400)
    
    if len(request.data.get('password1'))<=7 and len(request.data.get('password'))<=7:
        return Response({"msg":"Password must be at least 8 characters 😅"},status=400)
    
    serializer = UserSerializer(data=request.data,many=False)
    if serializer.is_valid():
        serializer.save()
        Profile.objects.create(
            user=User.objects.get(username=request.data.get('username')),
        )
        return Response({"msg":serializer.data},status=200)
    else:
        return Response({"msg":"Data is not valid. 😥"},status=400)

#!GET A SPECIFIC BLOG BY ID
@api_view(['GET'])
def GetBlog(request,pk):
    blog = Blog.objects.get(id=pk)
    serializer=BlogSerializer(blog,many=False)
    return Response({"msg":serializer.data},status=200)

#!GET ALL BLOGS IN DB
@api_view(['GET'])
def GetAllBlogs(request):
    blog = Blog.objects.all().order_by('-updated')
    serializer=BlogSerializer(blog,many=True)
    return Response({"msg":serializer.data},status=200)

#!CREATE A BLOG
@api_view(['POST'])
def CreateBlog(request):
    profile=Profile.objects.get(id=request.data.get('profile'))

    blog = Blog.objects.create(
        profile=profile,
        title=request.data.get('title'),
        description=request.data.get('description'),
        file=request.data.get('file'),
    )

    #?Title interests
    title = request.data.get('title')
    title = title.replace('.','')
    title = title.replace(',','')
    title = title.split(' ')
    for i in title:
        i=i.lower()
        for j in Interest.objects.filter(Q(tr_name__startswith=i[0]) | Q(en_name__endswith=i[0])):
            if difflib.SequenceMatcher(None,j.tr_name.lower(),i.lower()).ratio()>=0.6 or difflib.SequenceMatcher(None,j.en_name.lower(),i.lower()).ratio()>=0.6:
                profile.interests.add(j.id)
    

    #?Description interests
    desc = request.data.get('description')
    desc = desc.strip()
    desc = desc.replace('.','')
    desc = desc.replace(',','')
    desc = desc.split(' ')
    for i in desc:
        i=i.lower()
        for j in Interest.objects.filter(Q(tr_name__startswith=i[0]) | Q(en_name__endswith=i[0])):
            if difflib.SequenceMatcher(None,j.tr_name.lower(),i.lower()).ratio()>=0.6 or difflib.SequenceMatcher(None,j.en_name.lower(),i.lower()).ratio()>=0.6:
                profile.interests.add(j.id)

    
    serializer=BlogSerializer(blog,many=False)
    return Response({"msg":serializer.data,"success_msg":"Successfully created blog 🚀"},status=200)

#!EDIT A BLOG BY ID
@api_view(['PUT'])
def EditBlog(request,pk):
    blog = Blog.objects.get(id=pk)
    lang = request.data.get('language')
    if blog==None:
        if lang=="tr":
            return Response({"msg":"Blog bulunamadı. 😢"},status=404)
        else:
            return Response({"msg":"Blog not found. 😢"},status=404)
    fake_data = blog.editBlog(request.data)
    if request.data.get("removeFile"):
        fake_data['file']=None
    serializer=BlogSerializer(blog,data=fake_data)
    #?Description interests
    if request.data.get('description'):
        desc = request.data.get('description')
        desc = desc.replace('.','')
        desc = desc.replace(',','')
        desc = desc.split(' ')
        for i in desc:
            for j in Interest.objects.filter(Q(tr_name__startswith=i[0]) | Q(en_name__endswith=i[0])):
                if difflib.SequenceMatcher(None,j.tr_name.lower(),i.lower()).ratio()>=0.6 or difflib.SequenceMatcher(None,j.en_name.lower(),i.lower()).ratio()>=0.6:
                    blog.profile.interests.add(j.id)

    #?Title interests
    if request.data.get('title'):
        title = request.data.get('title')
        title = title.replace('.','')
        title = title.replace(',','')
        title = title.split(' ')
        for i in title:
            for j in Interest.objects.filter(Q(tr_name__startswith=i[0]) | Q(en_name__endswith=i[0])):
                if difflib.SequenceMatcher(None,j.tr_name.lower(),i.lower()).ratio()>=0.6 or difflib.SequenceMatcher(None,j.en_name.lower(),i.lower()).ratio()>=0.6:
                    blog.profile.interests.add(j.id)

    
    
    if serializer.is_valid():
        serializer.save()
        if request.data.get("language")=="tr":
            return Response({"msg":serializer.data,"success_msg":"Blog güncellendi. 🌝"},status=200)
        else:
            return Response({"msg":serializer.data,"success_msg":"Blog updated. 🌝"},status=200)
    else:
        if lang=="tr":
            return Response({"msg":serializer.data,"msg":"Bir hata oluştu. 😥"},status=400)
        else:
            return Response({"msg":serializer.data,"msg":"An error has accured. 😥"},status=400)

#!DELETE A BLOG
@api_view(['DELETE'])
def DeleteBlog(request,pk,lang):
    blog = Blog.objects.get(id=pk)
    if blog==None:
        if lang=="tr":
            return Response({"msg":"Blog bulunamadı. 😢"},status=404)
        else:
            return Response({"msg":"Blog not found. 😢"},status=404)
    blog.delete()
    if lang=="tr":
        return Response({"msg":"Blog silindi. 👍"},status=200)
    else:
        return Response({"msg":"Blog has been deleted. 👍"},status=200)

@api_view(['GET'])
def GetProfile(request,pk):
    profile = Profile.objects.filter(id=pk)
    if len(profile)>0:
        serializer = ProfileSerializer(profile[0],many=False)
        return Response({"msg":serializer.data},status=200)
    else:
        return Response({"msg":"Couldnt find the user 🤔"},status=404)

@api_view(['PUT'])
def EditProfile(request,pk):
    profile = Profile.objects.get(id=pk)
    if profile==None:
        return Response({"msg":"User not found 😢"},status=404)
    if request.data.get("description")!=None:
        profile.description = request.data.get("description")
    
    profile.interests.clear()
    if request.data.get("interests")!=None:
        for i in json.loads(request.data.get("interests")):
            profile.interests.add(i)
    if request.data.get("profilePic")!=None:
        profile.profilePic = request.data.get("profilePic")
    profile.save()
    serializer=ProfileSerializer(profile,many=False)
    if request.data.get("language")=="tr":
        return Response({"msg":serializer.data,"success_msg":"Profiliniz başarıyla düzenlendi. 🌝"},status=200)
    else:
        return Response({"msg":serializer.data,"success_msg":"Succesfully updated your profile. 🌝"},status=200)

@api_view(['GET'])
def GetAllInterests(request):
    interests = Interest.objects.all()
    serializer = InterestSerializer(interests,many=True)
    return Response({"msg":serializer.data},status=200)

@api_view(['POST'])
def FollowSomebody(request):
    will_be_followed = Profile.objects.filter(user=User.objects.get(id=request.data.get('will_be_followed')))
    will_follow = Profile.objects.filter(user=User.objects.get(id=request.data.get('will_follow')))
    lang = request.data.get('language')
    if len(will_be_followed)==1 and len(will_follow)==1:
        will_be_followed = Profile.objects.get(user=User.objects.get(id=request.data.get('will_be_followed')))
        will_follow = Profile.objects.get(user=User.objects.get(id=request.data.get('will_follow')))

        if will_follow.user not in will_be_followed.followers.all():
            will_be_followed.followers.add(will_follow.user.id)
            will_follow.following.add(will_be_followed.user.id)
            if lang=="tr":
                return Response({"msg":"Başarıyla takip edildi. 🚀"},status=200)
            return Response({"msg":"Successfully followed profile. 🚀"},status=200)
        else:
            will_be_followed.followers.remove(will_follow.user.id)
            will_follow.following.remove(will_be_followed.user.id)
            if lang=="tr":
                return Response({"msg":"Başarıyla takipten çıkıldı. 🚀"},status=200)
            return Response({"msg":"Successfully unfollowed profile. 🚀"},status=200)
        
    else:
        if lang=="tr":
            return Response({"msg":"Profil bulunamadı. 😒"},status=404)
        return Response({"msg":"Couldnt find the profile. 😒"},status=404)

@api_view(['POST'])
def ChangePassword(request):
    u = Profile.objects.get(id=request.data.get("id")).user
    auth = authenticate(username=u.username, password=request.data.get("old_password"))
    if auth==None:
        if request.data.get("language")=="tr":
            return Response({"msg":"Şuanki şifreniz doğru değil. 🤨"},status=400)
        else:
            return Response({"msg":"Current password is incorrect. 🤨"},status=400)
    
    if request.data.get("password")!=request.data.get("password1"):
        if request.data.get("language")=="tr":
            return Response({"msg":"Yeni şifreleriniz uyuşmuyor. 😒"},status=400)
        else:
            return Response({"msg":"New passwords dont match. 😒"},status=400)
    password = make_password(request.data.get("password"),hasher='default')
   
    u.set_password(request.data.get("password"))
    u.save()
    if request.data.get("language")=="tr":
        return Response({"msg":"Şifreniz değiştirildi. 👍"},status=200)
    else:
        return Response({"msg":"Changed your password. 👍"},status=200)

@api_view(['POST'])
def ResetPasswordMail(request):
    email = request.data.get("mail")
    lang = request.data.get("language")
    user = User.objects.get(email=email)
    if len(User.objects.filter(email=email))>0:
        jwt_code = jwt.encode(payload={"user_id":user.id,"username":user.username,'exp':datetime.now(timezone.utc)+timedelta(minutes=5)},key="alow31%4!")
        from django.template.loader import render_to_string
        link = "http://localhost:3000/reset-password/"+jwt_code+get_random_string(4).upper()
        template = render_to_string("base/email_reset.html",{"lang":lang,"link":link})
        if lang == "en":
            send_mail(
                'Reset your password 🤨',
                template,
                'info@peoplesjoint.com',
                [email],
                fail_silently=False,
            )
        else:
            send_mail(
                'Şifreni sıfırla 🤨',
                template,
                'info@peoplesjoint.com',
                [email],
                fail_silently=False,
            )
        if lang=="tr":
            return Response({"msg":"Email başarıyla gönderildi. 😄"},status=200)
        else:
            return Response({"msg":"Successfully sent mail. 😄"},status=200)
    else:
        if lang=="tr":
            return Response({"msg":str(email)+" emailiyle kayıt olmuş kullanıcı yok. 😒"},status=400)
        else:
            return Response({"msg":"There is no user saved with email "+str(email)+". 😒"},status=400)

@api_view(['POST'])
def ResetPassword(request,code):
    lang = request.data.get('lang')
    try:
        code = code[:len(code)-4]
        kod = jwt.decode(code,key="alow31%4!",algorithms=['HS256'],options={"verify_signature": True})
        
        id = kod.get("user_id")
        lang = request.data.get("lang")
        
        password1 = request.data.get("p_1")
        password2 = request.data.get("p_2")
        
        if password1 != password2:
            if lang=="tr":
                return Response({"msg":"Şifreler birbiriyle uyuşmuyor. 😒"},status=400)
            else:
                return Response({"msg":"Passwords dont match. 😒"},status=400)
        
        profile = Profile.objects.get(user=User.objects.get(id=id))
        
        if profile:
            profile.user.set_password(password1)
            profile.user.save()
            profile.save()
            if lang=="tr":
                return Response({"msg":"Şifre başarıyla değiştirildi. 😄"},status=200)
            else:
                return Response({"msg":"Password succesfully changed. 😄"},status=200)
        else:
            if lang=="tr":
                return Response({"msg":"Kullanıcı bulunamadı. 🤔"},status=400)
            else:
                return Response({"msg":"Couldn't find user. 🤔"},status=400)

        
    except:
        if lang=="tr":
            return Response({"msg":"Şifre şu an değiştirilemiyor. 😒"},status=400)
        else:
            return Response({"msg":"Can't change password now. 😒"},status=400)

@api_view(['POST'])
def ChangeMailSendMail(request):
    lang = request.data.get('lang')
    if len(User.objects.filter(id=request.data.get('id')))>0:
        user = User.objects.get(id=request.data.get("id"))
        jwt_code = jwt.encode(payload={"user_id":user.id,"username":user.username,'exp':datetime.now(timezone.utc)+timedelta(minutes=5)},key="alow31%4!")
        from django.template.loader import render_to_string
        link = "http://localhost:3000/change-email/"+jwt_code+get_random_string(4).upper()
        template = render_to_string("base/email_reset.html",{"lang":lang,"link":link})
        if lang == "en":
            send_mail(
                'Changing mail 🤨',
                template,
                'info@peoplesjoint.com',
                [user.email],
                fail_silently=False,
            )
        else:
            send_mail(
                'Mail değiştirme 🤨',
                template,
                'info@peoplesjoint.com',
                [user.email],
                fail_silently=False,
            )
        if lang=="tr":
            return Response({"msg":"Email başarıyla gönderildi. 😄"},status=200)
        else:
            return Response({"msg":"Successfully sent mail. 😄"},status=200)

    else:
        if lang=="tr":
            return Response ({"msg":"Kullanıcı bulunamadı. 😒"},status=400)
        else:
            return Response ({"msg":"User not found. 😒"},status=400)

@api_view(['POST'])
def ChangeMail(request,code):
    lang = request.data.get('language')
    mail = request.data.get('email')
    mail1 = request.data.get('email1')
    id = request.data.get('id')
    try:
        from django.template.loader import render_to_string
        if len(User.objects.filter(id=id))==0:
            if lang=="tr":
                return Response({"msg":"Kullanıcı bulunamadı. 😥"},status=200)
            else:
                return Response({"msg":"Couldnt find user. 😥"},status=200)
        user=User.objects.get(id=id)
        jwt_code = jwt.encode(payload={'user_id':user.id,'email':mail,'exp':datetime.now(timezone.utc)+timedelta(minutes=5)},key='alow31%4!')
        if mail1 == mail:
            link = "http://localhost:3000/confirm-email/"+jwt_code+str(get_random_string(4).upper())
            template = render_to_string("base/confirm_email_change.html",{"lang":lang,"link":link})
            if lang == "tr":
                send_mail(
                    'Email doğrulama 🌝',
                    template,
                    'info@peoplesjoint.com',
                    [mail],
                    fail_silently=False,
                )
            else:
                send_mail(
                    'Email confirmation 🌝',
                    template,
                    'info@peoplesjoint.com',
                    [mail],
                    fail_silently=False,
                )
            
            if lang=="tr":
                return Response({"msg":"Doğrulama maili başarıyla gönderildi. 😄"},status=200)
            else:
                return Response({"msg":"Conformation mail sent. 😄"},status=200)
        else:
            if lang=="tr":
                return Response({"msg":"Girdiğiniz mailler aynı değil. 🤨"},status=400)
            else:
                return Response({"msg":"The mails you entered dont match. 🤨"},status=400)
    except Exception as e:
        if lang=="tr":
            return Response ({"msg":"Şu anda mail değiştirilemiyor. 😒"},status=400)
        else:
            return Response ({"msg":"Cant change mail right now. 😒"},status=400)

@api_view(['POST'])
def ConfirmMail(request,code):
    lang = request.data.get('language')
    code = code[:len(code)-4]
    try:
        jwt_code = jwt.decode(code,key="alow31%4!",algorithms=['HS256'],options={"verify_signature": True})
        user = User.objects.get(id=jwt_code.get("user_id"))
        user.email=jwt_code.get("email")
        user.save()
        return Response({"msg":ProfileSerializer(Profile.objects.get(user=user)).data},status=200)
    except Exception as e:
        if lang=="tr":
            return Response ({"msg":"Şu anda mail değiştirilemiyor. 😒"},status=400)
        else:
            return Response ({"msg":"Cant change mail right now. 😒"},status=400)

def get_random_string(length):
    import string
    import random
    # choose from all lowercase letter
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str
    
@api_view(['POST'])
def LikeBlog(request,pk):
    lang = request.data.get("language")
    blog = Blog.objects.get(id=pk)
    profile = Profile.objects.filter(id=request.data.get("profile_id"))
    #TODO Kullanıcıyı kontrol etme
    if len(profile)==0:
        if lang == "en":
            return Response ({"msg":"Profile not found. 😶"},status=400)
        return Response ({"msg":"Kullanıcı bulunamadı. 😶"},status=400)
    profile = profile[0]
    #TODO Blogu beğenme
    if profile not in blog.likes.all():
        blog.likes.add(profile.id)
        if lang == "en":
            return Response ({"msg":"You liked the blog. 🌝","blog_data":BlogSerializer(blog).data},status=200)
        return Response ({"msg":"Blogu beğendiniz. 🌝","blog_data":BlogSerializer(blog).data},status=200)
    #TODO Blogu beğenmeyi geri çekme
    blog.likes.remove(profile.id)
    if lang == "en":
        return Response ({"msg":"You took your like back. 🤨","blog_data":BlogSerializer(blog).data},status=200)
    return Response ({"msg":"Beğeninizi geri çektiniz. 🤨","blog_data":BlogSerializer(blog).data},status=200)

def AnalyzeFollowings(pk):
    profile = Profile.objects.get(id=pk)
    array=[]
    count=0
    for i in profile.following.all():
        count=0
        for j in Blog.objects.filter(profile=Profile.objects.get(user=i)):
            if profile in j.likes.all():
                count+=1
        array.append([i.username,count,i.id])
    array.sort(key = lambda x: x[1],reverse=True)
    return array

@api_view(['GET'])
def ReccomendFriend(request,pk):
    array = AnalyzeFollowings(pk)
    people=[]
    import random
    for i in range(len(array)):
        profile = Profile.objects.get(user=User.objects.get(id=array[i][2]))
        if len(profile.following.all())>0:
            length = len(profile.following.all())
            random_int = random.randint(0,length-1)
            if profile.following.all()[random_int] not in people:
                people.append(ProfileSerializer(Profile.objects.get(user=profile.following.all()[random_int])).data)
        
    return Response({"msg":"Reccomended friends.","data":people},status=200)
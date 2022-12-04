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
    print(request.data)
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
    blog = Blog.objects.create(
        profile=Profile.objects.get(id=request.data.get('profile')),
        title=request.data.get('title'),
        description=request.data.get('description'),
        file=request.data.get('file'),
    )
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
    print(request.data)
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
    print(profile.profilePic,profile.description)
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
    profile = Profile.objects.get(id=request.data.get("id"))
    if profile:
        print(Profile.objects.get(id=request.data.get("profile")) in profile.followers.all())
        if Profile.objects.get(id=request.data.get("profile")) in profile.followers.all():
            profile.followers.remove(request.data.get("profile"))
        else:
            profile.followers.add(request.data.get("profile"))
        print(profile.followers.all())

        return Response({"msg":"Successfully followed profile"},status=200)
    else:
        return Response({"msg":"Couldnt find the profile"},status=404)

@api_view(['POST'])
def ChangePassword(request):
    u = Profile.objects.get(id=request.data.get("id")).user
    print(request.data)
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
    return Response("messi")
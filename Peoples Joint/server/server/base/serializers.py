from rest_framework import serializers
from .models import *
from rest_framework.serializers import ModelSerializer
from django.contrib.auth.models import User
from dateutil.tz import tzlocal
import pytz
from django.contrib.auth.password_validation import validate_password
import time

class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ['id','username','email','password','is_superuser','date_joined','last_login','is_authenticated']

        extra_kwargs = {'password':{
            'write_only':True,
            'required' :True
        }}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user


class ProfileSerializer(ModelSerializer):

    user = serializers.SerializerMethodField('getUser')

    class Meta:
        model       = Profile
        fields      = "__all__"

    def getUser(self,profile):
        if profile.user:
            return UserSerializer(profile.user,many=False).data
        else:
            return {"msg":"User not found 😥"}

    def getInterests(self,profile):
        array=[]
        if profile.interests:
            for i in profile.interests.all():
                array.append([i.name,i.id])
        return array

class BlogSerializer(ModelSerializer):
    
    profile = serializers.SerializerMethodField('getProfile')
    class Meta:
        model = Blog
        fields = "__all__"

    def to_representation(self, instance):
        if time.daylight:
            offsetHour = time.altzone / 3600
        else:
            offsetHour = time.timezone / 3600
        timezone='Etc/GMT%+d' % offsetHour
        self.fields['created'] = serializers.DateTimeField(default_timezone=pytz.timezone(timezone))
        self.fields['updated'] = serializers.DateTimeField(default_timezone=pytz.timezone(timezone))
        return super().to_representation(instance)

    def getProfile(self,blog):
        if blog.profile:
            return ProfileSerializer(blog.profile,many=False).data
        else:
            return {"msg":"User not found 😥"}

class InterestSerializer(ModelSerializer):

    class Meta:
       model = Interest
       fields = "__all__"
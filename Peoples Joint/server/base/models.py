from django.db import models
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
import json

interest_choices =(
    ("Football","Football"),
    ("Voleyball","Voleyball"),
    ("Combat Sports","Combat Sports"),
    ("Podcasting","Podcasting"),
    ("Sports","Sports"),
    ("Celebrities","Celebrities"),
    ("Talk Shows","Talk Shows"),
    ("News","News"),
    ("Politis","Politics"),
    ("Turkey","Turkey"),
    ("USA","USA"),
    ("Leo Messi","Leo Messi"),
    ("Ronaldo","Ronaldo"),
)

class Interest(models.Model):
    tr_name=models.CharField(max_length=100,null=False,blank=False)
    en_name=models.CharField(max_length=100,null=False,blank=False)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.tr_name + " ------ " + self.en_name

class Profile(models.Model):
    user = models.ForeignKey(User,on_delete=models.CASCADE,null=False,blank=False)
    profilePic = models.ImageField(null=True,blank=True,upload_to="profilePic")
    description = models.CharField(max_length=160,null=False,blank=True,default="No description was given.")
    followers = models.ManyToManyField("self",related_name='takipciler',default=None,blank=True)
    following = models.ManyToManyField("self",related_name='takip_edilenler',default=None,blank=True)
    interests = models.ManyToManyField(Interest,related_name='interests',blank=True)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.user.username

    @staticmethod
    def CheckProfile(request,username):
        user = User.objects.get(username=username)
        if len(Profile.objects.filter(user=user))>0:
            return True
        return False

class Blog(models.Model):
    profile = models.ForeignKey(Profile,on_delete=models.CASCADE,null=False,blank=False)
    title = models.CharField(max_length=100,null=False,blank=False)
    description = models.CharField(null=False,blank=False,max_length=240)
    file = models.FileField(null=True,blank=True,upload_to="blog_file")
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.profile.user.username+" ---------- "+self.title
    
    def editBlog(self,data):
        fake_data = data.copy()
        if fake_data.get("title")==None:
            fake_data['title']=self.title
        if fake_data.get("description")==None:
            fake_data['description']=self.description
        if fake_data.get("file")==None:
            fake_data['file']=self.file
        return fake_data 
from django.db import models
from django.contrib.auth.models import AbstractBaseUser,BaseUserManager,PermissionsMixin
from django.utils import timezone


class CustomUserManager(BaseUserManager):
    def _create_user(self,email,password,**extra_fields):
        if not email:
            return ValueError("Please Provide Proper Email Address")
        
        email=self.normalize_email(email)
        user=self.model(email=email,**extra_fields)
        user.set_password(password)
        user.save(using=self.db)
        return user
    
    def create_user(self,email=None,password=None,**extra_fields):
        extra_fields.setdefault('is_staff',False)
        extra_fields.setdefault('is_superuser',False)
        return self._create_user(email,password,**extra_fields)
    
    def create_superuser(self,email=None,password=None,**extra_fields):
        extra_fields.setdefault('is_staff',True)
        extra_fields.setdefault('is_superuser',True)
        return self._create_user(email,password,**extra_fields)
    

class UserRegistration(AbstractBaseUser,PermissionsMixin):

    email=models.EmailField(unique=True)
    password=models.CharField(max_length=255)
    full_name=models.CharField(max_length=255,null=True,blank=True)
    group = models.CharField(max_length=10, choices=(('owner', 'Owner'), ('staff', 'Staff')))
    otp=models.IntegerField(null=True,blank=True)
    otp_created_at=models.DateTimeField(auto_now_add=True,null=True,blank=True)
    user_created_at=models.DateTimeField(auto_now_add=True,null=True,blank=True)
    is_staff=models.BooleanField(default=False)
    is_active=models.BooleanField(default=True)
    is_superuser=models.BooleanField(default=False)
    is_valid=models.BooleanField(default=False)
    is_verified=models.BooleanField(default=False)
    is_registered=models.BooleanField(default=False)
    
    objects=CustomUserManager()
    
    USERNAME_FIELD='email'
    REQUIRED_FIELDS=[]
    
    def __str__(self):
        # return self.id
        return f"{self.email}-{self.group}"


class Staff(models.Model):
    name=models.ForeignKey(UserRegistration,on_delete=models.CASCADE,related_name='staff')
    phone_number = models.CharField(max_length=15,null=True,blank=True)
    address = models.TextField(null=True,blank=True)
    
    # def __str__(self):
    #     return self.name



class Company(models.Model):
    company_owner = models.ForeignKey(UserRegistration, on_delete=models.CASCADE, related_name='owned_companies')
    company_name = models.CharField(max_length=255)
    staff_member = models.ForeignKey(Staff, on_delete=models.CASCADE, related_name='company',null=True,blank=True)
    
    # def __str__(self):
    #     return self.company_owner
    

class File(models.Model):
    file_owner = models.ForeignKey(Staff, on_delete=models.CASCADE, related_name='files')
    file = models.FileField(upload_to='uploads/')
    created_at = models.DateTimeField(auto_now_add=True)
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='files',null=True,blank=True)

    
    

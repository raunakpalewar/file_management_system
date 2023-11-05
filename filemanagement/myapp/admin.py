from django.contrib import admin
from .models import *
# Register your models here.
admin.site.register(UserRegistration)
admin.site.register(Company)
admin.site.register(Staff)
admin.site.register(File)
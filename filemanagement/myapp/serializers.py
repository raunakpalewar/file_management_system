from rest_framework import serializers
from .models import *

class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRegistration
        fields = '__all__'
        partial = True  
        
class StaffSerializer(serializers.ModelSerializer):
    class Meta:
        model=File
        fields='__all__'

class FileSerializer(serializers.ModelSerializer):
    class Meta:
        model = File
        fields = '__all__'
        # read_only_fields = ('id', 'created_at')

class CompanySerializer(serializers.ModelSerializer):
    class Meta:
        model = Company
        fields = '__all__'
        # read_only_fields = ('id', 'created_at')
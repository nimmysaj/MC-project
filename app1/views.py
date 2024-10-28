from django.shortcuts import render
'''
# Create your views here.
from rest_framework import generics
from .models import User, Customer, ServiceProvider,OTP
from .serializers import UserSerializer, CustomerProfileSerializer, ServiceProviderProfileSerializer
from .serializers import OTPGenerateSerializer
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView


class RegisterUserView(generics.CreateAPIView):
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        data = request.data
        user = User.objects.create(
            username=data['username'],
            email=data['email'],
            phone_number=data['phone_number'],
            is_customer=data.get('is_customer', False),
            is_service_provider=data.get('is_service_provider', False),
        )
        user.set_password(data['password'])
        user.save()

        if user.is_customer:
            Customer.objects.create(user=user)
        if user.is_service_provider:
            ServiceProvider.objects.create(user=user)

        return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)



class CustomerProfileView(generics.RetrieveUpdateAPIView):
    queryset = Customer.objects.all()
    serializer_class = CustomerProfileSerializer


class ServiceProviderProfileView(generics.RetrieveUpdateAPIView):
    queryset = ServiceProvider.objects.all()
    serializer_class = ServiceProviderProfileSerializer



class GenerateOTPView(APIView):
    def post(self, request):
        serializer = OTPGenerateSerializer(data=request.data)
        if serializer.is_valid():
            otp = serializer.save()  # This generates and saves the OTP
            return Response({"message": "OTP sent successfully", "otp": otp.otp_code}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyOTPView(APIView):
    def post(self, request):
        username = request.data.get('username')
        otp_code = request.data.get('otp_code')

        try:
            user = User.objects.get(username=username)
            otp = OTP.objects.get(user=user, otp_code=otp_code)
            
            if otp.is_expired():
                return Response({"error": "OTP has expired"}, status=status.HTTP_400_BAD_REQUEST)

            return Response({"message": "OTP is valid"}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        except OTP.DoesNotExist:
            return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)
'''
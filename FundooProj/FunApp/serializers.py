from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework.response import Response


# creating a serializer class CreateUserSerializer which uses User Model
class CreateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'username', 'password','first_name','last_name']
        # extra_kwargs = {'email': {'unique': True}}
    #  method to create an database entry in the User model

    def create(self, validated_data):
        user = User(
                email=(validated_data['email']),  # getting the email
                username=validated_data['username'],   # getting the username
                first_name=validated_data['first_name'],   # getting the firstname
                last_name=validated_data['last_name']   # getting the lastname
        )
        if User.objects.filter(email=validated_data['email']).count() > 0:
            return "Email already exist"
        user.is_active = False  # making the is_active field to False
        user.set_password(validated_data['password'])  # setting the password for the user by hashing
        user.save()  # saving the user
        return user

    #  method to activate the user
    def validate(self, id, email):
        result = {
            'success': False,
            'message': 'Error occurred',
            'data': {}
        }
        try:
            user = User.objects.get(id=id)  # getting the user through the id
            if user.is_active is False:   # checking whether user is active
                user.is_active = True  # making user is_active to true for login purposes
                user.save()  # saving the user
                return Response({'message': 'User ACTIVATED'})
            else:
                raise ValueError
        except User.DoesnotExist:
            result.message = 'Invalid user'
            return Response(result)
        except ValueError:
            return Response({"message": "invalid"})

    def reset_email_password(self, email, password):
        valid_mail = email['email']  # getting the email of the user
        try:
            user = User.objects.get(email=valid_mail)  # getting the user from the email
            if user.is_active is True:  # checking whether the user is active or not
                user.set_password(password)  # setting the new password for the user
                user.save()  # saving the user
                return Response({'message': 'Password reset successfully done.'})
        except User.DoesNotExist:
            return Response({'message': 'Password reset failed.'})

    def get_user(self, email):
        valid_mail = email['email']
        try:
            user = User.objects.get(email=valid_mail)
            return user
        except Exception:
            print("in exception")
            return None

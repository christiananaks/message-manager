
from django.db import models
from django.core.validators import MinLengthValidator


# Create your models here.
class User(models.Model):
    objects = models.QuerySet()
    username = models.CharField(unique=True, max_length=16,
                                validators=[MinLengthValidator(6, 'Username must contain atleast 5 characters.')])
    phone_number = models.CharField(unique=True, max_length=16)
    client_number = models.CharField(max_length=16, unique=True)
    secret_question = models.JSONField()  # {question: ..., answer: ...}
    password = models.BinaryField()
    client_history = models.JSONField()


class RefreshToken(models.Model):
    objects = models.QuerySet()
    token = models.TextField()
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

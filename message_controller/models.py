from django.db import models


class Snapshot(models.Model):
    objects = models.QuerySet()
    android_id = models.CharField(unique=True, primary_key=True, max_length=16)
    brand = models.CharField(max_length=16)
    sim_cards = models.JSONField()
    message_snapshot = models.JSONField(unique=True)  # to be retrieved as list of dict
    date = models.DateTimeField(auto_now=True)

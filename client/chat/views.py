from django.shortcuts import render
from uniauth.decorators import login_required
import jwt
import os


@login_required
def index(request):
    token = jwt.encode({"username": request.user.username}, '#0wc-0-$@$14e8rbk#bke_9rg@nglfdc3&6z_r6nx!q6&3##l=',
            algorithm="HS256").decode("utf-8")
    return render(request, "chat/index.html",
            {"endpoint": "wss://mdhu4u131c.execute-api.ap-south-1.amazonaws.com/dev", "token": token})
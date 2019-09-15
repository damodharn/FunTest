from django.contrib import admin
from django.urls import path, include
from django.conf.urls import url
from rest_framework_swagger.views import get_swagger_view
schema_view = get_swagger_view(title="Swagger Docs")

urlpatterns = [
    path('', include('FunApp.urls')),
    path('admin/', admin.site.urls),
    url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    url(r'^', include('django.contrib.auth.urls')),
    # path('logout', views.logout),
    url(r'^swagger/', schema_view),
]
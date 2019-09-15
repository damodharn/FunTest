from django.urls import path,include
from . import views

urlpatterns = [
    path('', views.login, name='login'),
    path('home', views.home),
    path('forgot', views.forgot_password, name='forgot'),
    path('activate/<token>/', views.activate, name='activate'),
    path('reset/<token>/', views.reset, name='reset'),
    path('register', views.register,name='register'),
    path('logout', views.logout),
    path('upload', views.upload),
    path(r'^oauth/', include('social_django.urls', namespace='social')),
    path('loginsocial', views.loginsocial, name='loginsocial'),
    path('success', views.success),
    # path('Note', views.Note.as_view()),
    # path('Note/<int:pk>', views.Note.as_view()),
    # path('demo', views.demo, name='demo'),
    # path('add', views.add, name='add'),
    # path('reminder', views.reminder, name='reminder')
]
from django.conf import settings
from django.contrib import admin
from django.conf.urls.static import static
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('users/', include('users.urls', namespace='users')),
]


urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

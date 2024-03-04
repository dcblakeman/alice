from django.views.generic.edit import CreateView
from messaging.models import AuthenticatedMessage


class CreateAuthenticatedMessageView(CreateView):
    model = AuthenticatedMessage
    fields = ['message', 'hash_value', 'mac']
    success_url = '/'

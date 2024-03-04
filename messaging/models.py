from django.db import models
from django.db.models import Model, CharField
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
import hashlib
import hmac
from django.utils.encoding import force_bytes
from django.utils.translation import gettext_lazy as _


class AuthenticatedMessage(Model):
    message = CharField(max_length=100)
    hash_value = CharField(max_length=64)
    mac = CharField(max_length=64)
    validators = [RegexValidator(regex='^[0-9a-fA-F]{64}$')]

    def clean(self):
        hmac_function = hmac.new( b'frown canteen mounted carve', msg=force_bytes(self.message),
                                  digestmod=hashlib.sha256)
        hash_value = hmac_function.hexdigest()
        if not hmac.compare_digest(hash_value, self.hash_value):
            raise ValidationError(_('Message not authenticated'), code='msg_not_auth')


class Meta:
    permissions = [('send_authenticatedmessage', 'Can send msgs'),
                   ('receive_authenticatedmessage', 'Can receive msgs'), ]




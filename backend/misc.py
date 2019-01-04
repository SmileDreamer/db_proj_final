from flask_sqlalchemy import SQLAlchemy
from .models import *


def validate_request(json, action, params: dict):
    if "action" not in json or "param" not in json:
        return False
    if isinstance(action, str) and json["action"] != action:
        return False
    elif isinstance(action, (tuple, list)) and json["action"] not in action:
        return False
    for name, type in params.items():
        if name not in json["param"]:
            return False
        if not isinstance(json["param"][name], type):
            return False
    return True


def get_user(token):
    try:
        username = base64.b64decode(token.encode("utf-8")).decode("utf-8").split(":")[0]
    except:
        return None
    return User.query.filter_by(username=username).first()


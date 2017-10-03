import json
from functools import wraps

from flask import Flask, request
from jose import jwt

app = Flask(__name__)
ALGORITHMS = ["RS256"]


# Error handler
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = json.dumps(ex.error)
    response.status_code = ex.status_code
    return response

# get token
def get_token_auth_header():
    """
    Get access token from Authorization Header.
    :return:
    """
    auth = request.headers.get('Authorization', None)
    if not auth:
        raise AuthError({"code": "authorization_header_missing",
                         "description": "Authorization header is expected"}, 401)

    parts = auth.split()
    if parts[0].lower() != 'bearer':
        raise AuthError({"code": "invalid_header",
                         "description": "Authorization header must start with Bearer"}, 401)

    elif len(parts) == 1:
        raise AuthError({"code": "invalid_header",
                         "description": "Token not found"}, 401)

    elif len(parts) > 2:
        raise AuthError({"code": "invalid_header",
                         "description": "Authorization header must be Bearer token"}, 401)

    return parts[1]


def require_oauth(f):
    """
    Determines, if the access token is valid.
    :param f:
    :return:
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}
        jwks = request.data

        for key in jwks['keys']:
            if key["kid"] == unverified_header['kid']:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }

        if rsa_key:
            try:
                payload = jwt.decode(token, rsa_key, algorithms=ALGORITHMS)


            except jwt.ExpiredSignatureError:
                raise AuthError({"code": "token_expired",
                                 "description": "token is expired"}, 401)

            except jwt.JWTClaimsError:
                raise AuthError({"code": "invalid_claims",
                                 "description":
                                     "incorrect claims,"
                                     "please check the audience and issuer"}, 401)

            except Exception:
                raise AuthError({"code": "invalid_header",
                                 "description":
                                     "Unable to parse authentication"
                                     " token."}, 400)
            return f(*args, **kwargs)
        raise AuthError({"code": "invalid_header",
                         "description": "Unable to find appropriate key"}, 400)
    return decorated


@app.route('/secured/ping')
@require_oauth
def securedPing():
    return "All good."


if __name__ == '__main__':
    app.run()

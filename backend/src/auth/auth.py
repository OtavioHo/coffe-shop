import json
import jwt
import re
from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt
from urllib.request import urlopen
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend


AUTH0_DOMAIN = 'otavio.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'coffee-shop'

# AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


# Auth Header

def get_token_auth_header():

    auth = request.headers.get("Authorization", None)
    if not auth:
        raise AuthError({"code": "authorization_header_missing",
                         "description":
                         "Authorization header is expected"}, 401)

    parts = auth.split()

    if parts[0].lower() != "bearer":
        raise AuthError({"code": "invalid_header",
                         "description":
                         "Authorization header must start with"
                         " Bearer"}, 401)
    elif len(parts) == 1:
        raise AuthError({"code": "invalid_header",
                         "description": "Token not found"}, 401)
    elif len(parts) > 2:
        raise AuthError({"code": "invalid_header",
                         "description":
                         "Authorization header must be"
                         " Bearer token"}, 401)

    token = parts[1]
    return token


'''
@TODO implement check_permissions(permission, payload) method
    @INPUTS
        permission: string permission (i.e. 'post:drink')
        payload: decoded jwt payload

    it should raise an AuthError if permissions are not included in the payload
        !!NOTE check your RBAC settings in Auth0
    it should raise an AuthError if the requested permission string is not in the payload permissions array
    return true otherwise
'''


def check_permissions(permission, payload):
    if 'permissions' not in payload:
        raise AuthError({
            'code': 'invalid_claims',
            'description': 'Permissions not included in JWT.'
        }, 400)

    if permission not in payload['permissions']:
        raise AuthError({
            'code': 'unauthorized',
            'description': 'Permission not found.'
        }, 403)

    return True


'''
@TODO implement verify_decode_jwt(token) method
    @INPUTS
        token: a json web token (string)

    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    return the decoded payload

    !!NOTE urlopen has a common certificate error described here: https://stackoverflow.com/questions/50236117/scraping-ssl-certificate-verify-failed-error-for-http-en-wikipedia-org
'''


def verify_decode_jwt(token):
    token_header = jwt.get_unverified_header(token)

    # Verify if header has kid
    if 'kid' not in token_header:
        raise Exception('Invalid Token')

    url = "https://" + AUTH0_DOMAIN + "/.well-known/jwks.json"

    response = urlopen(url).read().decode('utf-8')
    JWKS = json.loads(response)
    # Find JWK with same kid

    def check_kid(jwk):
        if jwk['kid'] == token_header['kid']:
            return jwk

    valid_keys = list(map(check_kid, JWKS['keys']))
    if len(valid_keys) == 0:
        raise Exception('Invalid Token')

    my_jwk = valid_keys[0]

    # Building certification
    cert_string = my_jwk['x5c'][0]
    cert = '-----BEGIN CERTIFICATE-----\n' + \
        re.sub("(.{64})", "\\1\n", cert_string, 0, re.DOTALL) + \
        '-----END CERTIFICATE-----'
    cert_obj = load_pem_x509_certificate(
        cert.encode('ascii'), default_backend())
    public_key = cert_obj.public_key()

    # Decoding JWT
    try:
        decode = jwt.decode(token, public_key,
                            algorithms=ALGORITHMS[0], audience=API_AUDIENCE)
    except jwt.ExpiredSignatureError:
        raise Exception('Signature has expired')

    return decode


'''
@TODO implement @requires_auth(permission) decorator method
    @INPUTS
        permission: string permission (i.e. 'post:drink')

    it should use the get_token_auth_header method to get the token
    it should use the verify_decode_jwt method to decode the jwt
    it should use the check_permissions method validate claims and check the requested permission
    return the decorator which passes the decoded payload to the decorated method
'''


def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator

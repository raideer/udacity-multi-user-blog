import hmac
import hashlib
import string
import random

# hashes the value using our secret
def make_secure_val(val, secret):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

# checks if the hash is genuine
def check_secure_val(secure_val, secret):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val, secret):
        return val

# makes a salt for hashing passwords
def make_salt(length = 5):
    return ''.join(random.choice(string.letters) for x in xrange(length))

# makes a password hash with sha256
def make_password_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt,h)

# checks if the password hash matches with the name and password
def check_password_hash(name, pw, h):
    salt,hash = h.split(',')
    return make_password_hash(name, pw, salt) == h

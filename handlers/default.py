import webapp2
import re
import jinja2
import os
from json import dumps as jsondump
from urllib import urlencode
from google.appengine.ext import db

import utilities
import models

jinja_env = None
secret = 'bR>Fb397J@gM(nB\LNn*jHX'

def setSecret(s):
    global secret
    secret = s

def setTemplatePath(template_dir):
    global jinja_env
    jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

def authorized(f):
    def wrapper(self, *args, **kwargs):
        user = self.getCurrentUser(return_model = True)
        if not user:
            self.logout()
            return self.redirect('/user/login')

        kwargs['user'] = user
        f(self, *args, **kwargs)
    return wrapper

def unauthorized(f):
    def wrapper(self, *args, **kwargs):
        if self.getCurrentUser():
            return self.redirect('/user/profile')

        f(self, *args, **kwargs)
    return wrapper

# default request handler
class DefaultHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        kw['user'] = self.getCurrentUser()
        self.write(self.render_str(template, **kw))

    # returns a json object instead of string/template
    def returnJson(self, object):
        self.response.headers['Content-Type'] = "application/json"
        self.response.out.write(jsondump(object))

    # hashes and sets a cookie
    def setCookie(self, name, val):
        cookie_val = utilities.make_secure_val(str(val), secret)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    # reads and validates a cookie
    def readCookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and utilities.check_secure_val(cookie_val, secret)

    # basic input validation
    def validUsername(self, username):
        return re.compile(r"^[a-zA-Z0-9_-]{3,20}$").match(username)
    def validEmail(self, email):
        return re.compile(r"^[\S]+@[\S]+.[\S]+$").match(email)
    def validPassword(self, password):
        return re.compile(r"^.{3,20}$").match(password)

    # checks if the username is not taken
    def uniqueUsername(self, username):
        return not models.User.get_by_name(username)

    # returns id and name of the current logged in user
    # if return_model is True
    #   user Model is returned instead
    def getCurrentUser(self, return_model = False):
        user_id = self.readCookie('user_id')
        user = self.readCookie('user')
        if user_id and user:
            current_user = {'id': int(user_id), 'name': str(user)}
            if return_model:
                u = models.User.get_by_id(current_user['id'])
                return u
            else:
                return current_user

    # set user cookies if the login was successful
    def login(self, user):
        self.setCookie('user_id', str(user.key().id()))
        self.setCookie('user', user.username)

    # clears all cookies responsible for user authorization
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.response.headers.add_header('Set-Cookie', 'user=; Path=/')

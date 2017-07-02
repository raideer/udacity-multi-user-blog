# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import webapp2
import jinja2
import re
import hashlib
import hmac
import string
import random
from json import dumps as jsondump
from urllib import urlencode

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

secret = 'bR>Fb397J@gM(nB\LNn*jHX'

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val
def make_salt(length = 5):
    return ''.join(random.choice(string.letters) for x in xrange(length))
def make_password_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt,h)
def check_password_hash(name, pw, h):
    salt,hash = h.split(',')
    return make_password_hash(name, pw, salt) == h

class User(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.EmailProperty(required=False)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def get_by_name(self, name):
        u = self.all().filter('username =', name).get()
        return u

    @classmethod
    def login(self, username, password):
        u = self.get_by_name(username)
        if u:
            if check_password_hash(username, password, u.password):
                return u

# Required for strong consistency
POST_ROOT = db.Key.from_path('Post', 'post_root')

class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    author = db.ReferenceProperty(User, collection_name='posts', required=True)
    liked_by = db.ListProperty(db.Key)
    disliked_by = db.ListProperty(db.Key)

class Comment(db.Model):
    post = db.ReferenceProperty(Post, collection_name='comments', required=True)
    author = db.ReferenceProperty(User, collection_name='comments', required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    content = db.TextProperty(required=True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        kw['user'] = self.getCurrentUser()
        self.write(self.render_str(template, **kw))

    def returnJson(self, object):
        self.response.headers['Content-Type'] = "application/json"
        self.response.out.write(jsondump(object))

    def setCookie(self, name, val):
        cookie_val = make_secure_val(str(val))
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    def validUsername(self, username):
        return re.compile(r"^[a-zA-Z0-9_-]{3,20}$").match(username)

    def validEmail(self, email):
        return re.compile(r"^[\S]+@[\S]+.[\S]+$").match(email)

    def validPassword(self, password):
        return re.compile(r"^.{3,20}$").match(password)

    def uniqueUsername(self, username):
        return not User.get_by_name(username)

    def getCurrentUser(self, return_model = False):
        user_id = self.readCookie('user_id')
        user = self.readCookie('user')
        if user_id and user:
            current_user = {'id': int(user_id), 'name': str(user)}
            if return_model:
                u = User.get_by_id(current_user['id'])
                return u
            else:
                return current_user

    def login(self, user):
        self.setCookie('user_id', str(user.key().id()))
        self.setCookie('user', user.username)

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.response.headers.add_header('Set-Cookie', 'user=; Path=/')

    def readCookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

# For pages that require user to be logged in
class AuthorizedHandler(Handler):
    def dispatch(self):
        user = self.getCurrentUser()

        if not user:
            self.logout() # clear all cookies just to make sure
            return self.redirect('/user/login')
        super(AuthorizedHandler, self).dispatch()

# For pages that require user to be logged out
class UnauthorizedHandler(Handler):
    def dispatch(self):
        if self.getCurrentUser():
            return self.redirect('/user/profile')
        super(UnauthorizedHandler, self).dispatch()

class UserRegister(UnauthorizedHandler):
    def get(self):
        self.render('signup/signup.html', errors = {})
    def post(self):
        username = self.request.get('username')
        email = self.request.get('email')
        password = self.request.get('password')
        verify = self.request.get('verify')

        errors = {}

        if not self.validUsername(username):
            errors['username'] = "That's not a valid username"
        if not username:
            errors['username'] = "Please enter a username"
        if not self.uniqueUsername(username):
            errors['username'] = "That username is already taken"

        if email and not self.validEmail(email):
            errors['email'] = "That's not a valid email"

        if not self.validPassword(password):
            errors['password'] = "That's not a valid password"
        if not password:
            errors['password'] = "Please enter a password"
        if password != verify:
            errors['verify'] = "Your passwords didn't match"

        if len(errors) > 0 :
            return self.render('signup/signup.html', errors = errors, username = username, email = email)
        else:
            pwhash = make_password_hash(username, password)
            user = User(username = username, password = pwhash)
            if email:
                user.email = email
            user.put()

            self.login(user)
            self.redirect('/user/profile')

class UserLogout(AuthorizedHandler):
    def get(self):
        self.logout()
        self.redirect('/user/login')

class UserLogin(UnauthorizedHandler):
    def get(self):
        self.render('signup/login.html', error = False)
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        user = User.login(username, password)
        if not user:
            return self.render('signup/login.html', error = True)
        else:
            self.login(user)
            self.redirect('/user/profile')

class UserProfile(AuthorizedHandler):
    def get(self):
        u = self.getCurrentUser(return_model = True)
        self.render('signup/profile.html', u = u)

class Blog(Handler):
    def get(self):
        posts = Post.all().order('-created').ancestor(POST_ROOT)
        self.render('blog/index.html', posts = posts)

class BlogPost(Handler):
    def get(self, postId):
        post = Post.get_by_id(int(postId), POST_ROOT)
        self.render('blog/post.html', post = post)

class BlogDeletePost(AuthorizedHandler):
    def get(self, postId):
        post = Post.get_by_id(int(postId), POST_ROOT)
        user = self.getCurrentUser(return_model = True)
        if post.author.key() == user.key():
            self.render('blog/deletepost.html', post = post)
        else:
            self.write("You can only delete your own posts!")
    def post(self, postId):
        post = Post.get_by_id(int(postId), POST_ROOT)
        user = self.getCurrentUser(return_model = True)
        if post.author.key().id() == user.key().id():
            post.delete()
        self.redirect('/')

class BlogRatePost(AuthorizedHandler):
    def post(self, postId, action):
        post = Post.get_by_id(int(postId), POST_ROOT)
        user = self.getCurrentUser(return_model = True)

        if post.author.key() != user.key():
            # If user hasn't voted yet
            if user.key() not in post.liked_by and user.key() not in post.disliked_by:
                if action == 'upvote':
                    post.liked_by.append(user.key())
                elif action == 'downvote':
                    post.disliked_by.append(user.key())
            # If user has already upvoted
            elif user.key() in post.liked_by and user.key() not in post.disliked_by:
                post.liked_by.remove(user.key())
                if action == 'downvote':
                    post.disliked_by.append(user.key())
            #If user has already disliked
            elif user.key() not in post.liked_by and user.key() in post.disliked_by:
                post.disliked_by.remove(user.key())
                if action == 'upvote':
                    post.liked_by.append(user.key())

            post.put()

            votes = len(post.liked_by) - len(post.disliked_by)
            self.returnJson({'votes': votes})
        else:
            self.returnJson({'error': "You can't rate your own posts!"})

class BlogCommentPost(AuthorizedHandler):
    def post(self, postId):
        post = Post.get_by_id(int(postId), POST_ROOT)
        user = self.getCurrentUser(return_model = True)
        content = self.request.get('content')
        if user:
            comment = Comment(parent=post.key(), post=post, author=user, content=content)
            comment.put()
            self.redirect('/post/' + str(post.key().id()))

class BlogDeleteComment(AuthorizedHandler):
    def post(self):
        postKey = db.Key(self.request.get('post_key'))
        commentId = self.request.get('comment_id')
        user = self.getCurrentUser(return_model = True)

        if postKey and commentId and user:
            comment = Comment.get_by_id(int(commentId), postKey)
            if comment:
                comment.delete()
        self.redirect('/post/'+str(postKey.id()))

class BlogEditComment(AuthorizedHandler):
    def post(self):
        postKey = db.Key(self.request.get('post_key'))
        commentId = self.request.get('comment_id')
        content = self.request.get('content')
        user = self.getCurrentUser(return_model = True)

        if content and postKey and commentId and user:
            comment = Comment.get_by_id(int(commentId), postKey)
            if comment:
                comment.content = content
                comment.put()
        self.redirect('/post/'+str(postKey.id()))

class BlogEditPost(AuthorizedHandler):
    def get(self, postId):
        post = Post.get_by_id(int(postId), POST_ROOT)
        user = self.getCurrentUser(return_model = True)
        if post.author.key() == user.key():
            self.render('blog/editpost.html', post = post)
        else:
            self.write("You can only edit your own posts!")
    def post(self, postId):
        subject = self.request.get('subject')
        content = self.request.get('content')

        post = Post.get_by_id(int(postId), POST_ROOT)

        if not post:
            return self.redirect('/')

        user = self.getCurrentUser(return_model = True)

        if post.author.key() == user.key():
            if subject and content:
                post.subject = subject
                post.content = content
                post.put()

                self.redirect('/post/' + str(post.key().id()))
            else:
                error = "Title and content is REQUIRED"
                self.render('blog/editpost.html', post = post)
        else:
            return self.write("You can only edit your own posts!")

class BlogNewPost(AuthorizedHandler):
    def get(self):
        self.render('blog/newpost.html')
    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        user = self.getCurrentUser(return_model = True)

        if subject and content and user:
            post = Post(parent = POST_ROOT, subject = subject, content = content, author = user)
            post.put()

            self.redirect('/post/' + str(post.key().id()))
        else:
            error = "Title and content is REQUIRED"
            self.render('blog/newpost.html', error = error, subject = subject, content = content)

app = webapp2.WSGIApplication([
    ('/user/signup', UserRegister),
    ('/user/profile', UserProfile),
    ('/user/login', UserLogin),
    ('/user/logout', UserLogout),
    ('/', Blog),
    ('/newpost', BlogNewPost),
    (r'/post/(\d+)', BlogPost),
    (r'/post/(\d+)/edit', BlogEditPost),
    (r'/post/(\d+)/delete', BlogDeletePost),
    (r'/post/(\d+)/comment', BlogCommentPost),
    (r'/comment/delete', BlogDeleteComment),
    (r'/comment/edit', BlogEditComment),
    (r'/post/(\d+)/(upvote|downvote)', BlogRatePost)
], debug=True)

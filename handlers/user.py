from default import *

# Login handler
# Accessible only by users that are logged out
class Login(DefaultHandler):
    @unauthorized
    def get(self):
        self.render('user/login.html', error = False)
    @unauthorized
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        user = models.User.login(username, password)
        # if the username/password combination is incorrect
        # return to the login page
        if not user:
            return self.render('user/login.html', error = True)
        else:
            self.login(user)
            self.redirect('/user/profile')

# Logout handler
# Accessible only by users that are logged in
class Logout(DefaultHandler):
    @authorized
    def get(self, user):
        self.logout()
        self.redirect('/user/login')

# User registration handler
# Accessible only by guests
class Register(DefaultHandler):
    @unauthorized
    def get(self):
        self.render('user/signup.html', errors = {})
    @unauthorized
    def post(self):
        username = self.request.get('username')
        email = self.request.get('email')
        password = self.request.get('password')
        verify = self.request.get('verify')

        errors = {}

        # input validation
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

        # show errors if there are any
        if len(errors) > 0 :
            return self.render('user/signup.html', errors = errors, username = username, email = email)
        else:
            # else complete the registration
            pwhash = utilities.make_password_hash(username, password)
            user = models.User(username = username, password = pwhash)
            if email:
                user.email = email
            user.put()

            self.login(user)
            self.redirect('/user/profile')

# User profile handler
# Accessible only by users that are logged in
class Profile(DefaultHandler):
    @authorized
    def get(self, user):
        self.render('user/profile.html', u = user)

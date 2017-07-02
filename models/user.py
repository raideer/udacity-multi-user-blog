from google.appengine.ext import db
from utilities import check_password_hash

class User(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.EmailProperty(required=False)
    created = db.DateTimeProperty(auto_now_add=True)

    # finds a user with the provided name
    @classmethod
    def get_by_name(self, name):
        u = self.all().filter('username =', name).get()
        return u

    # returns the user model if the user and password combination is correct
    @classmethod
    def login(self, username, password):
        u = self.get_by_name(username)
        if u:
            if check_password_hash(username, password, u.password):
                return u

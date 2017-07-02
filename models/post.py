from google.appengine.ext import db
from user import User
# post Model
# represents a Post
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    author = db.ReferenceProperty(User, collection_name='posts', required=True)
    liked_by = db.ListProperty(db.Key)
    disliked_by = db.ListProperty(db.Key)

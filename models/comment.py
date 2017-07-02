from google.appengine.ext import db
from user import User
from post import Post

# comment Model
# represents a Comment in a Post
class Comment(db.Model):
    post = db.ReferenceProperty(Post, collection_name='comments', required=True)
    author = db.ReferenceProperty(User, collection_name='comments', required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    content = db.TextProperty(required=True)

from default import *
from blog import has_post

# Handles commenting
class Create(DefaultHandler):
    @authorized
    @has_post
    def post(self, post_id, user, post):
        content = self.request.get('content')
        comment = models.Comment(parent=post.key(), post=post, author=user, content=content)
        comment.put()
        self.redirect('/post/' + str(post.key().id()))

# Handles comment deletion
class Delete(DefaultHandler):
    @authorized
    def post(self, user):
        # creating a database Key
        # required for strong consistency
        postKey = db.Key(self.request.get('post_key'))
        commentId = self.request.get('comment_id')

        if postKey and commentId:
            comment = models.Comment.get_by_id(int(commentId), postKey)
            if comment:
                comment.delete()
        self.redirect('/post/'+str(postKey.id()))

# Handles comment editing
class Edit(DefaultHandler):
    @authorized
    def post(self, user):
        postKey = db.Key(self.request.get('post_key'))
        commentId = self.request.get('comment_id')
        content = self.request.get('content')

        if content and postKey and commentId:
            comment = models.Comment.get_by_id(int(commentId), postKey)
            if comment:
                comment.content = content
                comment.put()
        self.redirect('/post/'+str(postKey.id()))

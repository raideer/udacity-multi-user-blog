from default import *

# Required for strong consistency
# https://cloud.google.com/datastore/docs/articles/balancing-strong-and-eventual-consistency-with-google-cloud-datastore/
POST_ROOT = db.Key.from_path('Post', 'post_root')

def has_post(f):
    def wrapper(self, post_id, *args, **kw):
        key = db.Key.from_path('Post', int(post_id), parent = POST_ROOT)
        post = db.get(key)

        if post:
            kw['post'] = post
            return f(self, post_id, *args, **kw)

        return self.error(404)
    return wrapper

# Blog handler
class Index(DefaultHandler):
    def get(self):
        # Returns all posts ordered by 'created' descending
        # ancestor method makes sure that the posts we see are up to date
        #
        # otherwise if you delete a post, it will not disappear immediately
        # after page refresh
        posts = models.Post.all().order('-created').ancestor(POST_ROOT)
        self.render('blog/index.html', posts = posts)

# Blog post handler
class Post(DefaultHandler):
    @has_post
    def get(self, post_id, post):
        self.render('blog/post.html', post = post)

# Handles post upvoting/downvoting
class RatePost(DefaultHandler):
    # see routing to understand where post_id and action comes from
    # action can either be 'upvote' or 'downvote'
    @authorized
    @has_post
    def post(self, post_id, action, post, user):
        # Check if user is not the author of the post
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

            # since this request is made via ajax post request (to avoid refreshing),
            # we are returning json data
            #
            # see the bottom of ./template.html for more information
            self.returnJson({'votes': votes})
        else:
            self.returnJson({'error': "You can't rate your own posts!"})

# Handles post creation
class NewPost(DefaultHandler):
    @authorized
    def get(self, user):
        self.render('blog/newpost.html')
    @authorized
    def post(self, user):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post = models.Post(parent = POST_ROOT, subject = subject, content = content, author = user)
            post.put()

            self.redirect('/post/' + str(post.key().id()))
        else:
            error = "Title and content is REQUIRED"
            self.render('blog/newpost.html', error = error, subject = subject, content = content)

# Handles post deletion
class DeletePost(DefaultHandler):
    @authorized
    @has_post
    def get(self, post_id, post, user):
        # Checks if the user is author of the post
        if post.author.key() == user.key():
            self.render('blog/deletepost.html', post = post)
        else:
            self.write("You can only delete your own posts!")
    @authorized
    @has_post
    def post(self, post_id, post, user):
        # Rechecks if the user is author of the post
        if post.author.key() == user.key():
            post.delete()
        self.redirect('/')

# Handles post editing
class EditPost(DefaultHandler):
    @authorized
    @has_post
    def get(self, post_id, post, user):
        # check if user is author of the post
        if post.author.key() == user.key():
            self.render('blog/editpost.html', post = post)
        else:
            self.write("You can only edit your own posts!")
    @authorized
    @has_post
    def post(self, post_id, post, user):
        subject = self.request.get('subject')
        content = self.request.get('content')

        # cehck if user is author of the post
        if post.author.key() == user.key():
            # making sure subject and content inputs exist before
            # we overwrite the post
            if subject and content:
                post.subject = subject
                post.content = content
                post.put()

                self.redirect('/post/' + str(post.key().id()))
            else:
                error = 'Subject and content is REQUIRED'
                self.render('blog/editpost.html', post = post, error = error)
        else:
            return self.write("You can only edit your own posts!")

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

import webapp2
import os

import handlers

handlers.setTemplatePath(os.path.join(os.path.dirname(__file__), 'templates'))

# Routing
app = webapp2.WSGIApplication([
    ('/user/signup',                    handlers.user.Register),
    ('/user/profile',                   handlers.user.Profile),
    ('/user/login',                     handlers.user.Login),
    ('/user/logout',                    handlers.user.Logout),

    ('/',                               handlers.blog.Index),
    ('/newpost',                        handlers.blog.NewPost),
    (r'/post/(\d+)',                    handlers.blog.Post),
    (r'/post/(\d+)/edit',               handlers.blog.EditPost),
    (r'/post/(\d+)/delete',             handlers.blog.DeletePost),
    (r'/post/(\d+)/(upvote|downvote)',  handlers.blog.RatePost),

    (r'/post/(\d+)/comment',            handlers.comment.Create),
    (r'/comment/delete',                handlers.comment.Delete),
    (r'/comment/edit',                  handlers.comment.Edit)

], debug=True)

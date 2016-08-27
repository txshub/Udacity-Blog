import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

secret = 'somereallyrandomtext'

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        if self.user:
            params['username_str'] = self.username_str
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
        if uid:
            self.username_str = User.by_id(int(uid)).name

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

#----------------------------------------------------------

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

# The class representing the user table--------------------

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

# The class representing the post table--------------------

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    owner = db.StringProperty(required = True)
    likes = db.IntegerProperty(required = True, default = 0)

    def render(self, **params):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p = self, **params)

    def liked_by(self, user_str):
        for like in self.like_set:
            if like.user.name == user_str:
                return True
        return False

# The class representing the comment table-----------------

class Comment(db.Model):
    owner = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    post = db.ReferenceProperty(Post, required = True)

# The class representing the like table--------------------

class Like(db.Model):
    user = db.ReferenceProperty(User, required = True)
    post = db.ReferenceProperty(Post, required = True)

# The class handling the first page------------------------

class BlogFront(BlogHandler):
	def get(self):
		posts = db.GqlQuery("select * from Post order by created desc limit 10")
		self.render('front.html', posts = posts)

# The class handling the individual post page--------------

class PostPage(BlogHandler):
	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent = blog_key())
		p = db.get(key)

		if not p:
			self.error(404)
			return

		self.render("permalink.html", post = p, comments = p.comment_set)

# The class handling the page for creating a new post------

class NewPost(BlogHandler):
	def get(self):
		if self.user:
			self.render("newpost.html")
		else:
			self.redirect("/login")

	def post(self):
		if not self.user:
			self.redirect('/blog')

		subject = self.request.get('subject')
		content = self.request.get('content')

		if subject and content:
			p = Post(parent = blog_key(), owner = self.username_str, subject = subject, content = content)
			p.put()
			self.redirect('/blog/post/%s' % str(p.key().id()))
		else:
			error = "Please enter both the subject and some content!"
			self.render("newpost.html", subject = subject, content = content, error = error)

# Class handling the page for editing a post

class EditPost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        p = db.get(key)

        if not p:
            self.error(404)
            return

        if not self.user:
            self.redirect('/login')
            return

        if not p.owner == self.username_str:
            self.render("error.html", msg = "You are not allowed to edit someone else's post!")
            return

        self.render("newpost.html", subject = p.subject, content = p.content)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        p = db.get(key)

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p.subject = subject
            p.content = content
            p.put()
            self.redirect('/blog/post/%s' % str(p.key().id()))
        else:
            error = "Please enter both the subject and some content!"
            self.render("newpost.html", subject=subject, content=content, error=error)

# Class handling the page for deleting a post--------------

class DeletePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent = blog_key())
        p = db.get(key)

        if not p:
            self.error(404)
            return

        if not self.user:
            self.redirect('/login')
            return

        if not p.owner == self.username_str:
            self.render("error.html", msg = "You are not allowed to delete someone else's post!")
            return

        for comment in p.comment_set:
            comment.delete()
        p.delete()
        self.redirect('/blog/')

# The class handling the page for creating a new comment---

class NewComment(BlogHandler):
    def get(self, post_id):
        if self.user:
            self.render("comment-form.html")
        else:
            self.redirect("/login")

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not self.user:
            self.redirect("/login")
            return

        content = self.request.get('content')

        if content:
            comment = Comment(owner = self.username_str, content = content, post = post)
            comment.put()
            self.redirect("/blog/post/" + post_id)
        else:
            error = "Please enter some content!"
            self.render("comment-form.html", error = error)

# Class handling the page for editing a comment------------

class EditComment(BlogHandler):
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        c = db.get(key)

        if not c:
            self.error(404)
            return

        if not self.user:
            self.redirect('/login')
            return

        if not c.owner == self.username_str:
            self.render("error.html", msg = "You are not allowed to edit someone else's comment!")
            return

        self.render("comment-form.html", content = c.content)

    def post(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        c = db.get(key)

        content = self.request.get('content')

        if content:
            c.content = content
            c.put()
            self.redirect('/blog/post/' + str(c.post.key().id()))
        else:
            error = "Please enter some content!"
            self.render("comment-form.html", error = error)

# Class handling the page for deleting a comment-----------

class DeleteComment(BlogHandler):
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        c = db.get(key)

        if not c:
            self.error(404)
            return

        if not self.user:
            self.redirect('/login')
            return

        if not c.owner == self.username_str:
            self.render("error.html", msg = "You are not allowed to delete someone else's comment!")
            return

        post_id = str(c.post.key().id())
        c.delete()
        self.redirect('/blog/post/' + post_id)

# Class handling a like------------------------------------

class LikePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        if not self.user:
            self.redirect('/login')
            return

        if self.username_str == post.owner:
            self.render("error.html", msg = "You are not allowed to like or unlike your own posts!")
            return

        user = User.by_name(self.username_str)
        if post.liked_by(self.username_str):
            self.redirect('/blog/post/' + post_id)
            return

        like = Like(user = user, post = post)
        like.put()
        post.likes += 1
        post.put()
        self.redirect('/blog/post/' + post_id)

# Class handling an unlike---------------------------------

class UnlikePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        if not self.user:
            self.redirect('/login')
            return

        if self.username_str == post.owner:
            self.render("error.html", msg = "You are not allowed to like or unlike your own posts!")
            return

        for like in post.like_set:
            if like.user.name == self.username_str:
                post.likes -= 1
                post.put()
                like.delete()
                self.redirect('/blog/post/' + post_id)
                return

        self.redirect('/blog/post/' + post_id)

#----------------------------------------------------------

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

# Class handling the signup page---------------------------

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username, email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

# Class handling the login page----------------------------

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

# Class handling the logout page---------------------------

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

#----------------------------------------------------------

class MainPage(BlogHandler):
    def get(self):
		self.write('Hello, Udacity!')

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/blog/?', BlogFront),
    ('/blog/post/([0-9]+)', PostPage),
    ('/blog/editpost/([0-9]+)', EditPost),
    ('/blog/deletepost/([0-9]+)', DeletePost),
    ('/blog/newpost', NewPost),
    ('/blog/newcomment/([0-9]+)', NewComment),
    ('/blog/editcomment/([0-9]+)', EditComment),
    ('/blog/deletecomment/([0-9]+)', DeleteComment),
    ('/blog/like/([0-9]+)', LikePost),
    ('/blog/unlike/([0-9]+)', UnlikePost),
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout)
], debug=True)

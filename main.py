from flask import Flask, render_template, redirect, url_for, flash, abort, Response
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.orm import declarative_base

app = Flask(__name__)
app.app_context().push()
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
# One database with 2 tables
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# create a LoginManager object to use methods in LoginManager class.
login_manager = LoginManager()
# configure it for login
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    '''You will need to provide a user_loader callback.
    This callback is used to reload the user object from the user ID
    stored in the session. It should take the str ID of a user, and
    return the corresponding user object.'''
    return User.query.get(int(user_id))


# gravatar image for the comment
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# In our blog, the first registered user will be the admin.
# They will be able to create new blog posts, edit posts and delete posts.
# The first user's id is 1. We can use this in index.html and post.html to
# make sure that only the admin user can see the "Create New Post" and "Edit Post"
# and Delete buttons.

# CONFIGURE TABLES
# In relational databases such as SQLite, MySQL or Postgresql we're able to define a
# relationship between tables using a ForeignKey and a relationship() method.
# e.g. If we wanted to create a One to Many relationship between the User Table and the
# BlogPost table, where One User can create Many BlogPost objects, we can use the
# SQLAlchemy docs to achieve this.
# https://docs.sqlalchemy.org/en/13/orm/basic_relationships.html


class User(UserMixin, db.Model):
    # Inherit from UserMixin, which provides default implementations for all of required properties and methods.
    # https://flask-login.readthedocs.io/en/latest/#your-user-class
    # Note: A Mixin is simply a way to provide multiple inheritance to Python. This is how you add a Mixin:
    # # class MyClass(MixinClassB, MixinClassA, BaseClass):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")
    # *******Add parent relationship*******#
    # "comment_author" refers to the comment_author property in the Comment class.
    comments = relationship("Comment", back_populates="comment_author")


# Line below only required once, when creating DB.
# db.create_all()

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # Establish a One to Many relationship Between the User Table (Parent)
    # and the BlogPost table (Child).
    # Create Foreign Key, "user.id" the user refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    # Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    # the author property of BlogPost is now a User object.
    author = relationship("User", back_populates="posts")

    # Establish a One to Many relationship between each BlogPost object (Parent)
    # and Comment object (Child). Where each BlogPost can have many associated Comment objects.
    # "comment_blog" refers to the comment_blog property in the Comment class.
    post_comments = relationship("Comment", back_populates="parent_post")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)

    # Establish a One to Many relationship Between the User Table (Parent)
    # and the Comment table (Child). Where One User is linked to Many Comment objects.
    # *******Add child relationship*******#
    # "users.id" The users refers to the tablename of the Users class.
    # "comments" refers to the comments property in the User class.
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    comment_author = relationship("User", back_populates="comments")

    # Establish a One to Many relationship between each BlogPost object (Parent)
    # and Comment object (Child). Where each BlogPost can have many associated Comment objects.
    # *******Add child relationship*******#
    blog_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="post_comments")

    text = db.Column(db.Text, nullable=False)


db.create_all()


def admin_only(f):
    '''Create admin-only decorator'''
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id == 1:
            return f(*args, **kwargs)
        else:
            return abort(403)
    # Renaming the function name: to be able to use more than one decorators
    # as the function name will be the same (wrapper_function) which will cause
    # an error
    wraps.__name__ = f.__name__
    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    # You can access the logged-in user with the current_user proxy (current_user.is_authenticated)
    return render_template("index.html", all_posts=posts, current_user=current_user)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # check if the email already exists in the database
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash("You have already signed up with that email. Log in instead!")
            return redirect(url_for('login'))
        else:
            # register a new user
            hash_and_salted_password = generate_password_hash(form.password.data,
                                                              method='pbkdf2:sha256',
                                                              salt_length=8)
            new_user = User(email=form.email.data,
                            password=hash_and_salted_password, name=form.name.data)
            db.session.add(new_user)
            db.session.commit()
            # This line will authenticate the user with Flask-Login
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        # find the user by the email they entered in the login form.
        user = User.query.filter_by(email=email).first()

        # check if the user exists
        if user:
            # checking the password entered hashed against stored password hash in the database.
            if check_password_hash(user.password, password):
                # login_user() function is used to authenticate the user.
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash("Incorrect Password. Please try again")
                return redirect(url_for('login'))
        else:
            flash("The email doesn't exist. Please try again")
            return redirect(url_for('login'))
    else:
        return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()

    if form.validate_on_submit():
        # if the user is logged in
        if current_user.is_authenticated:
            comment = form.comment_text.data
            new_comment = Comment(text=comment,
                                  comment_author=current_user,
                                  parent_post=requested_post)
            db.session.add(new_comment)
            db.session.commit()
            # comments = Comment.query.all()
            return redirect(url_for('show_post', post_id=post_id))
        else:
            flash("You need to log in or register to comment")
            return redirect(url_for('login'))

    # comments = Comment.query.all()
    return render_template("post.html", post=requested_post, current_user=current_user, form=form)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            # the author property of BlogPost is now a User object.
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=current_user,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)

'''Admin
   Email: admin@email.com
   Password: AdminIsPretty
   Name: Admin'''

'''User
   Email: angela@email.com
   Password: AngelaIsPretty
   Name: A'''

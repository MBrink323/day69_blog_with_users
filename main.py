from flask import Flask, render_template, redirect, url_for, flash, abort
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


def admin_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            # ensure user is logged in to check current_user.id
            if current_user.id == 1:
                return function(*args, **kwargs)
            else:
                return abort(403)
        else:
            return abort(403)
    return decorated_function


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# initialize gravatar for graphics
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # author = db.Column(db.String(250), nullable=False)
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comments = relationship("Comment", back_populates="post")


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")


class Comment(db.Model):
    __tablename__="comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text(1000))
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    post = relationship("BlogPost", back_populates="comments")


# #only required once to create new table
# with app.app_context():
#     db.create_all()


login_manager = LoginManager()
login_manager.init_app(app)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    register_user_form = RegisterForm()
    new_user = User()
    if register_user_form.validate_on_submit():
        new_user.name = register_user_form.username.data
        new_user.email = register_user_form.email.data
        # generate hashed and salted password
        new_user.password = generate_password_hash(register_user_form.password.data, salt_length=8)
        with app.app_context():
            if User.query.filter_by(email=register_user_form.email.data).first():
                flash("You have already an account. Please Log In")
                return redirect(url_for("login"))
        # continue only in case user not existing
        with app.app_context():
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=register_user_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        with app.app_context():
            email = login_form.email.data
            password = login_form.password.data
            logged_in_user = User.query.filter_by(email=email).first()
            if logged_in_user:
                if check_password_hash(logged_in_user.password, password):
                    login_user(logged_in_user)
                    flash("Logged in successfully")
                    return redirect(url_for("get_all_posts"))
                else:
                    flash("Wrong Password. Please try again")
            else:
                flash("The Email does not exist. Please try again")
    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    # app_context required for complete function due to access of post.html to db required to get details of author
    with app.app_context():
        requested_post = BlogPost.query.get(post_id)
        comment_form = CommentForm()
        if comment_form.validate_on_submit():
            new_comment = Comment(
                text=comment_form.comment.data,
                author=current_user,
                post=requested_post,
            )
            if current_user.is_authenticated:
                # with app.app_context():
                db.session.add(new_comment)
                db.session.commit()
            else:
                flash("Please log in to leave a comment")
                return redirect(url_for("login"))
        return render_template("post.html", post=requested_post, form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        with app.app_context():
            db.session.add(new_post)
            db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    with app.app_context():
        post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        with app.app_context():
            db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    with app.app_context():
        post_to_delete = BlogPost.query.get(post_id)
        db.session.delete(post_to_delete)
        db.session.commit()
    return redirect(url_for('get_all_posts'))


@login_manager.user_loader
def load_user(user_id):
    with app.app_context():
        user = User.query.get(user_id)
    return user


if __name__ == "__main__":
    app.run(debug=True)

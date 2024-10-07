from flask import Flask,render_template,request,redirect,flash,url_for,jsonify
from flask_login import UserMixin,current_user
from flask_sqlalchemy import SQLAlchemy
from wtforms import Form,StringField,SubmitField,PasswordField,ValidationError,BooleanField,TextAreaField,FileField
from wtforms.validators import EqualTo,Email,DataRequired,Length,Regexp
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import login_user,LoginManager,logout_user,login_required
from itsdangerous import TimedSerializer as serializer
from flask import current_app
from flask_mail import Mail,Message
import os
from datetime import datetime
from flask_moment import Moment
from base64 import b64encode
from werkzeug.utils import secure_filename
import uuid as uuid
from sqlalchemy import or_

app=Flask(__name__)
app.config['SECRET_KEY']='Thisisasecretkey'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///test.db'

db=SQLAlchemy(app,session_options={"autoflush":False})
moment=Moment(app)
login_manager=LoginManager(app)

class Follow(db.Model):
    follower_id=db.Column(db.Integer,db.ForeignKey('users.id'),primary_key=True)
    followed_id=db.Column(db.Integer,db.ForeignKey('users.id'),primary_key=True)
    timestamp=db.Column(db.DateTime,default=datetime.utcnow)

class Messages(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    sender_id=db.Column(db.Integer,nullable=False)
    recipants_id=db.Column(db.Integer,nullable=False)
    body=db.Column(db.Text)
    photo=db.Column(db.LargeBinary)
    timestamp=db.Column(db.DateTime,default=datetime.utcnow)

class Like(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    liker_id=db.Column(db.Integer,db.ForeignKey('users.id'))
    post_id=db.Column(db.Integer,db.ForeignKey('posts.id'))

class Comment(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    body=db.Column(db.String)
    datetime=db.Column(db.DateTime,default=datetime.utcnow)
    commenter_id=db.Column(db.Integer,db.ForeignKey('users.id'))
    post_id=db.Column(db.Integer,db.ForeignKey('posts.id'))

class Posts(db.Model):
    __tablename__='posts'
    id=db.Column(db.Integer,primary_key=True)
    user_id=db.Column(db.Integer)
    file_name=db.Column(db.String,unique=True,index=True)
    post=db.Column(db.LargeBinary,nullable=False)
    caption=db.Column(db.String,nullable=True)
    location=db.Column(db.String,nullable=True)
    postby=db.Column(db.String,nullable=False)
    datetime=db.Column(db.DateTime,default=datetime.utcnow)

    likes=db.relationship('Like',backref='post',lazy='dynamic')
    comments=db.relationship('Comment',backref='post',lazy='dynamic')
    
class User(db.Model,UserMixin):
    __tablename__='users'
    id=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(64))
    email=db.Column(db.String(64),unique=True,index=True)
    username=db.Column(db.String(64),unique=True,index=True)
    password_hash=db.Column(db.String(128))
    confirmed=db.Column(db.Boolean,default=False)
    location=db.Column(db.String(64))
    about_me=db.Column(db.Text())
    member_since=db.Column(db.DateTime(),default=datetime.utcnow)
    last_seen=db.Column(db.DateTime(), default=datetime.utcnow)
    profilepic=db.Column(db.LargeBinary(),nullable=True)
    
    followed=db.relationship('Follow',
                             foreign_keys=[Follow.follower_id],
                             backref=db.backref('follower',lazy='joined'),
                             lazy='dynamic',
                             cascade='all,delete-orphan')
    followers=db.relationship('Follow',
                              foreign_keys=[Follow.followed_id],
                              backref=db.backref('followed',lazy='joined'),
                              lazy='dynamic',
                              cascade='all,delete-orphan')
    likes=db.relationship('Like',
                          backref='likes',
                          lazy='dynamic')
    
    comments=db.relationship('Comment',backref='comments',lazy='dynamic')

    @property
    def password(self):
        raise AttributeError('Password is not readable attribute')
    @password.setter
    def password(self,password):
        self.password_hash=generate_password_hash(password)
    def verify_password(self,password):
        return check_password_hash(self.password_hash,password)

    def ping(self):
        self.last_seen=datetime.UTC
        db.session.add(self)

    def is_following(self,username):
        user=User.query.filter_by(username=username).first()
        return self.followed.filter_by(followed_id=user.id).first() is not None
    
    def is_followed_by(self,username):
        user=User.query.filte(username=username)
        return self.followers.filter_by(follower_id=user.id).first() is not None
    
    def followed_posts(self):
        return Posts.query.join(Follow, Follow.followed_id == Posts.user_id).filter(Follow.follower_id == self.id)
     
    def has_liked_post(self,post):
        return Like.query.filter_by(liker_id=self.id,
                                    post_id=post.id).first () is not None
    
    def like_post(self,post):
        if not self.has_liked_post(post):
            like=Like(liker_id=self.id,post_id=post.id)
            db.session.add(like)
            db.session.commit()
    
    def unlike_post(self,post):
        if self.has_liked_post(post):
            post_like=Like.query.filter_by(liker_id=self.id,post_id=post.id).first()
            db.session.delete(post_like)
            db.session.commit()

class Registration_form(Form):
    name=StringField('What is your name?',[DataRequired()])
    email=StringField('Email',[Email(),DataRequired(),Length(1,30)])
    username=StringField('Username',[DataRequired(),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,'Usernames must have only letters, numbers,dots or underscores')])
    password=PasswordField('Password',[EqualTo('confpass','Passwords must match'),DataRequired(),Length(6,10)])
    confpass=PasswordField('confirm password',[DataRequired()])
    submit=SubmitField('Submit')

    def validate_email(self,field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already register')
       
    def validate_username(self,field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use')

class loginform(Form):
    email=StringField('Email',[Email(),DataRequired(),Length(1,64)])
    password=PasswordField('Password',[DataRequired()])
    remember_me=BooleanField('Keep me looged in')
    login=SubmitField('Log In')

class EditProfileForm(Form):
    name=StringField('Your name ',[Length(0,64)])
    location=StringField('Location ',[Length(0,64)])
    about_me=TextAreaField('About me')
    profile_pic=FileField('Profile Pic')
    submit=SubmitField('Submit')

class Postform(Form):
    caption=TextAreaField('Caption ',[Length(0,128)])
    location=StringField('Location',[Length(0,32)])
    post=SubmitField('Post')

class Commentform(Form):
    body=TextAreaField()
    post=SubmitField('post')

@app.route('/register',methods=['GET','POST'])
def Register():
    form=Registration_form(request.form)
    if form.validate():
        user=User(email=form.email.data,
                  name=form.name.data,
                  username=form.username.data,
                  password=form.password.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('register.html',form=form)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

@app.route('/login',methods=['GET','POST'])
def login():
    form=loginform(request.form)
    if form.validate():
        user=User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user,form.remember_me.data)
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html',form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for('index'))

@app.route('/main',methods=['GET','POST'])
def index():
    if current_user.is_authenticated:
        posts=current_user.followed_posts()
        posts=posts.order_by(Posts.datetime.desc())
        for post in posts:
            profilepic=User.query.filter_by(id=post.user_id).first().profilepic
            if profilepic:
                profilepic=b64encode(profilepic).decode("utf-8")
            setattr(post,"profilepic",profilepic)
            post.post=b64encode(post.post).decode("utf-8")
        if current_user.profilepic:
            profilepic=b64encode(current_user.profilepic).decode("utf-8")
            return render_template('index.html',posts=posts,profilepic=profilepic)
        return render_template('index.html',posts=posts)
    return render_template('index.html')
 
@app.route('/user/<username>')
def user(username):
    user=User.query.filter_by(username=username).first()
    posts=Posts.query.filter_by(user_id=user.id).all()
    for i in range(len(posts)):
        posts[i].post=b64encode(posts[i].post).decode("utf-8")  
    if user.profilepic:
        profilepic=b64encode(user.profilepic).decode("utf-8")
        return render_template('user.html',user=user,posts=posts,profilepic=profilepic)
    return render_template('user.html',user=user,posts=posts)


@app.route('/user/edit-profile',methods=['GET','POST'])
@login_required
def edit_profile():
    form=EditProfileForm(request.form)
    if request.method=='POST' and form.validate():
        current_user.name=form.name.data
        current_user.location=form.location.data
        current_user.about_me=form.about_me.data
        img_data=request.files['profilepic']
        if img_data:
            current_user.profilepic=img_data.read()
        flash('Your profile has been updated')
        db.session.commit()
        return redirect(url_for('user',username=current_user.username))
    form.name.data=current_user.name
    form.location.data=current_user.location
    form.about_me.data=current_user.about_me
    return render_template('edit-profile.html',form=form)

@app.route('/post',methods=['GET','POST'])
@login_required
def post():
    form=Postform(request.form)
    if form.validate() and request.method=='POST':
        post_file=request.files['image']
        postname=secure_filename(post_file.filename)
        post=Posts(user_id=current_user.id,
                   post=post_file.read(),
                   file_name=str(uuid.uuid1())+"_"+postname,
                   postby=current_user.username,
                   caption=form.caption.data,
                   location=form.location.data)
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('user',username=current_user.username))
    return render_template('post.html',form=form)

@app.route('/user/<username>/post/<file_name>')
def post_view(username,file_name):
    user=User.query.filter_by(username=username).first()
    profile_pic=None
    if user.profilepic:
        profile_pic=b64encode(user.profilepic).decode("utf-8")
    post_file=Posts.query.filter_by(file_name=file_name).first()
    post_file.post=b64encode(post_file.post).decode("utf-8")
    return render_template('Post_view.html',user=user,post_file=post_file,profile_pic=profile_pic)

@app.route('/user/<username>/<post>/edit-post',methods=['GET','POST'])
@login_required
def edit_post(username,post):
    form=Postform(request.form)
    post=Posts.query.filter_by(file_name=post).first()
    if form.validate() and request.method=='POST':
        post.caption=form.caption.data
        post.location=form.location.data
        db.session.commit()
        return redirect(url_for('post_view',username=post.postby,file_name=post.file_name))
    form.caption.data=post.caption
    form.location.data=post.location
    return render_template('edit_post.html',form=form)

@app.route('/del/<file_name>')
def del_post(file_name):
    post=Posts.query.filter_by(file_name=file_name).first()
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('user',username=current_user.username))

@app.route('/follow/<username>')
@login_required
def follow(username):
    user=User.query.filter_by(username=username).first()
    if not user:
        print("no user")
        return redirect(url_for('user',username=username))
    f=Follow(follower_id=current_user.id,followed_id=user.id)
    db.session.add(f)
    db.session.commit()
    return redirect(url_for('user',username=username))

@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user=User.query.filter_by(username=username).first()
    if not user:
        return redirect(url_for('user',username=username))
    f=current_user.followed.filter_by(followed_id=user.id).first()
    if f:
        db.session.delete(f)
        db.session.commit()
    return redirect(url_for('user',username=username))

@app.route('/post/<post_file>/like')
@login_required
def like(post_file):
    post=Posts.query.filter_by(file_name=post_file).first()
    current_user.like_post(post)
    likes_count=post.likes.count()
    return jsonify({'likes':likes_count})

@app.route('/post/<post_file>/unlike')
@login_required
def unlike(post_file):
    post=Posts.query.filter_by(file_name=post_file).first()
    current_user.unlike_post(post)
    likes_count=post.likes.count()
    return jsonify({'likes':likes_count})

@app.route('/post/<post_id>/comment',methods=['POST'])
@login_required
def comment(post_id):
    text=request.form['content']
    post=Posts.query.filter_by(id=post_id).first_or_404()
    comment=Comment(body=text,commenter_id=current_user.id,post_id=post.id)
    db.session.add(comment)
    db.session.commit()
    return jsonify({'message':"Comment successfully posted"})

@app.route('/post/<post_id>/comments', methods=['GET'])
def get_comments(post_id):
    comments=Comment.query.filter_by(post_id=post_id).order_by(Comment.datetime.desc()).all()
    
    for comment in comments:
        username=User.query.filter_by(id=comment.commenter_id).first().username
        setattr(comment,"username",username)
    comments_data=[{'content':comment.body,'user':comment.username,'datetime':comment.datetime,'comment_id':comment.id} for comment in comments]
    return jsonify(comments_data)


@app.route('/post/<post_id>/likes',methods=['GET'])
def likes(post_id):
    likes=Like.query.filter_by(post_id=post_id).all()
    for i in range(len(likes)):
        user=User.query.filter_by(id=likes[i].liker_id).first()
        setattr(likes[i],'username',user.username)
        if user.profilepic:
            setattr(likes[i],'profilepic',b64encode(user.profilepic).decode("utf-8"))
    return render_template('likes.html',likes=likes)

@app.route('/search',methods=['GET'])
def search_users():
    query=request.args.get('query')
    search="%{}%".format(query)
    results=User.query.filter(User.username.like(search)).all()
    for user in results:
        if user.profilepic:
            user.profilepic=b64encode(user.profilepic).decode("utf-8")
    user_data=[{'id':user.id, 'username':user.username, 'profilepic':user.profilepic} for user in results]
    return jsonify(user_data)
@app.route('/message/<username>')
@login_required
def message(username):
    user=User.query.filter_by(username=username).first()
    if not user:
        return redirect('user',username=username)
    if user.profilepic:
        user.profilepic=b64encode(user.profilepic).decode("utf-8")
    return render_template('message.html',user=user)

@app.route('/send_message/<username>',methods=['POST','GET'])
@login_required
def send_message(username):
    user=User.query.filter_by(username=username).first_or_404()
    message=request.form['body']
    msg=Messages(body=message,
                recipants_id=user.id,
                sender_id=current_user.id)
    print(msg)
    db.session.add(msg)
    db.session.commit()
    return jsonify({'message':"sent"})
@app.route('/get_message/<username>',methods=['get','POST'])
@login_required
def get_message(username):
    user=User.query.filter_by(username=username).first()
    msgs_data=Messages.query.filter(or_(
        (Messages.sender_id==current_user.id)&(Messages.recipants_id==user.id),
        (Messages.sender_id==user.id)&(Messages.recipants_id==current_user.id)
    )).order_by(Messages.timestamp.asc()).all()
    for msg in msgs_data:
        user=User.query.filter_by(id=msg.sender_id).first()
        setattr(msg,"username",user.username)
    msgs=[{'username':msg.username,'body':msg.body,'timestamp':msg.timestamp} for msg in msgs_data]
    return jsonify(msgs)

@app.route('/show_DM',methods=['GET'])
@login_required
def show_DM():
    senders=Messages.query.filter_by(recipants_id=current_user.id).distinct(Messages.sender_id).all()
    recipients=Messages.query.filter_by(sender_id=current_user.id).distinct(Messages.recipants_id).all()
    sender_dms=[]
    for sender in senders:
        user=User.query.filter_by(id=sender.sender_id).first()
        sender_dms.append(user)
    recipients_dms=[]
    for recipient in recipients:
        user=User.query.filter_by(id=recipient.recipants_id).first()
        recipients_dms.append(user)
    dms=set(sender_dms+recipients_dms)
    for dm in dms:
        if dm.profilepic:
            dm.profilepic=b64encode(dm.profilepic).decode("utf-8")
    people=[{'username':dm.username,'profilepic':dm.profilepic} for dm in dms]
    return jsonify(people)

if __name__=="__main__":
    app.run(debug=True)

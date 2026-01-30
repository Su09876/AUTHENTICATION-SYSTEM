from flask import Flask, render_template, redirect, url_for, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField
from wtforms.validators import DataRequired, Email, ValidationError
import bcrypt
from flask_mysqldb import MySQL
from flask import request


app = Flask(__name__)

import os

app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')


mysql = MySQL(app)

class RegisterForm(FlaskForm):
    name = StringField("Name",validators=[DataRequired()])
    email = StringField("Email",validators=[DataRequired(), Email()])
    password = PasswordField("Password",validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self,field):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users where email=%s",(field.data,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            raise ValidationError('Email Already Taken')

class LoginForm(FlaskForm):
    email = StringField("Email",validators=[DataRequired(), Email()])
    password = PasswordField("Password",validators=[DataRequired()])
    submit = SubmitField("Login")



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register',methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        hashed_password = bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())

        # store data into database 
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (name,email,password) VALUES (%s,%s,%s)",(name,email,hashed_password))
        mysql.connection.commit()
        cursor.close()

        return redirect(url_for('login'))

    return render_template('register.html',form=form)

@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s",(email,))
        user = cursor.fetchone()
        cursor.close()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[3]):
            session['user_id'] = user[0]
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed. Please check your email and password")
            return redirect(url_for('login'))

    return render_template('login.html',form=form)

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users where id=%s",(user_id,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            return render_template('dashboard.html',user=user)
            
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))

@app.route('/delete-account', methods=['POST'])
def delete_account():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
    mysql.connection.commit()
    cursor.close()

    session.pop('user_id', None)
    flash("Your account has been deleted successfully.")

    return redirect(url_for('login'))

@app.route('/edit-profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    cursor = mysql.connection.cursor()

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']

        cursor.execute(
            "UPDATE users SET name=%s, email=%s WHERE id=%s",
            (name, email, user_id)
        )
        mysql.connection.commit()
        cursor.close()

        flash("Profile updated successfully.")
        return redirect(url_for('dashboard'))

    cursor.execute("SELECT name, email FROM users WHERE id=%s", (user_id,))
    user = cursor.fetchone()
    cursor.close()

    return render_template('edit_profile.html', user=user)



if __name__ == '__main__':
    app.run(debug=True)
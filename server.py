from flask import Flask, render_template, request, redirect, session, flash
from models import connectToMySQL
app = Flask(__name__)
app.secret_key = '1dhiy6avy121489siigjcxjvkllsjkfd'
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)
import random
import re
user_rex = re.compile(r'^[A-Za-z0-9_]+$')
password_rex = re.compile(r'^(?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*[!@#$%^&*]).{4,24}$')

#Reders Homepage
@app.route('/') 
def renderHomepage():
    mysql = connectToMySQL('button_game')
    query = 'SELECT * FROM users JOIN points ON users.id = points.user_id ORDER BY points DESC;'
    total_points = mysql.query_db(query)
    return render_template("homepage.html", total_points= total_points)   

#Renders Signup Page
@app.route('/signup')
def renderSignup():
    return render_template("signup.html")

#Renders Login Page
@app.route('/login')
def renderLogin():
    return render_template("login.html")

#Checks if Logged in and Renders Button Game
@app.route('/button')
def arelogged():
    if session.get('logged_in'):
        username = session['username']
        #Shows points
        mysql = connectToMySQL('button_game')
        query = 'SELECT * FROM users JOIN points ON users.id = points.user_id ORDER BY points DESC;'
        total_points = mysql.query_db(query)
        #Shows current user points
        mysql = connectToMySQL('button_game')
        query = 'SELECT * FROM points WHERE user_id=%(user_id)s;'
        data = {
            "user_id" : session['id']
            }
        getpoints = mysql.query_db(query, data)
        session['points'] = getpoints[0]["points"]
        #Shows comments
        mysql = connectToMySQL('button_game')
        querry = 'SELECT * FROM users JOIN comments ON users.id = comments.user_id ORDER BY comments.id DESC;'
        comments = mysql.query_db(querry)
        return render_template("button.html", username=username, total_points= total_points, comments=comments, points = session['points'])
    else:
        return redirect('/') 

#signup page and adds to database 
@app.route('/signup', methods=['POST'])
def registration():
    #Looks through the datebase for existing users
    is_valid = True
    mysql = connectToMySQL('button_game')       
    query = 'SELECT * FROM users WHERE username=%(username)s;'
    data = {
        "username" : request.form['username']
    }
    existing_users = mysql.query_db(query, data)
    #Checks for username requirements
    if len(request.form['username']) < 1 or not user_rex.match(request.form['username']): 
        is_valid = False
        flash("Please enter a valid username")
        return redirect('/signup')
    #Checks if the user exists
    if existing_users:
        is_valid = False
        flash("Username already in use")
        return redirect('/signup')
    #Checks for password requirements
    if not password_rex.match(request.form['password']):
        is_valid = False
        flash("Please enter a password")
        return redirect('/signup')
    #Check if the confirmation password matches the entered password
    if request.form['password'] != request.form['confirm_pw']: 
        is_valid = False
        flash("Password does not match")
        # print('false')    
        return redirect('/signup')
    #addes new user to the database
    if is_valid:         
        password = bcrypt.generate_password_hash(request.form['password'])
        data = {
                "username" : request.form["username"],
                "password" : password
                }
        mysql = connectToMySQL('button_game')         
        query = "INSERT INTO button_game.users (username, password, created_at) VALUES (%(username)s, %(password)s, NOW());"
        userid = mysql.query_db(query, data)
        session['id']= userid
        data = {
                "points" : int(0),
                "user_id" : session['id']
        }
        mysql = connectToMySQL('button_game')
        query = "INSERT INTO button_game.points (points, user_id, created_at) VALUES (%(points)s, %(user_id)s, NOW());"
        mysql.query_db(query, data)
        session['username'] = request.form['username']
        session['logged_in'] = True 
        return redirect('/button')

#login 
@app.route('/login', methods=['POST']) 
def login():
    mysql = connectToMySQL('button_game')
    query = 'SELECT * FROM users WHERE username=%(username)s;'
    data = {
        "username" : request.form['username']
        }       
    query_result = mysql.query_db(query, data)
    #Checks for the entered username in the database
    if not query_result:
        flash('Username/Password is incorrect')
        return redirect('/login')
    pw_hash = query_result[0]["password"]
    password_check = bcrypt.check_password_hash(pw_hash,request.form['password'])
    if query_result: 
        if password_check:
            session['username'] = query_result[0]["username"]
            session['id'] = query_result[0]["id"]
            session['logged_in'] = True
            return redirect('/button')
    else:
        flash("Username/Password is incorrect")
        return redirect('/login')

#adds and takes away points updates the data base
@app.route('/button', methods=['GET','POST'])
def gainLoss():
    session['points'] = int(session['points']) + random.randint(-5,10)
    mysql = connectToMySQL('button_game')
    query = "UPDATE points SET points= %(points)s, updated_at = NOW() WHERE user_id= %(user_id)s;"
    data = {
        "user_id" : session['id'],
        "points" : session['points']
        }
    mysql.query_db(query, data)    
    return redirect('/button')

#Comments Section for writing comments
@app.route('/comment/create', methods= ['POST'])  
def createComments():
    if len(request.form['message'])>255 or len(request.form['message'])<1:
        flash('Invalid amount of characters')
        return redirect('/button')    
    else:    
        mysql = connectToMySQL('button_game')       
        query = "INSERT INTO comments (comment, user_id, created_at) VALUES (%(comment)s, %(user_id)s, NOW());"
        data = {
            "comment" : request.form["message"],
            "user_id" : session['id']
            }
        mysql.query_db(query, data)
        flash('Posted!')
        return redirect('/button')      

#Clears the session and Logged off
@app.route('/logout', methods=['GET','POST'])
def arelogout():
    session['logged_in'] = False
    return redirect('/')    
        
if __name__ == "__main__":
    app.run(debug=True)


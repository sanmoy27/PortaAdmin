from flask import Flask, flash, render_template, request, Response, json, redirect, url_for, session, jsonify, make_response, g
from flask_mysqldb import MySQL
from flask_sqlalchemy import SQLAlchemy
import sqlite3
import uuid
from flask_cors import CORS, cross_origin
from werkzeug.exceptions import BadRequest
from flask_api import status
import datetime
import send_sms_email
import pyotp
import json
from flask_mail import Mail, Message
from flask_login import LoginManager, login_user, logout_user
from flask_oauthlib.client import OAuth
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
with open('config.json', 'r') as json_data_file:
    config = json.load(json_data_file)


app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisissecretkeyformyapp'
cors = CORS(app, resources={r"/*": {"origins": "*"}})
app.config['CORS_HEADERS'] = 'Content-Type'

####### CONFIGURE MAIL SERVER ##############
app.config['DEBUG'] = True
app.config['TESTING'] = False
app.config['MAIL_SERVER'] = config['MAIL_SERVER']
app.config['MAIL_PORT'] = config['MAIL_PORT']
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
#app.config['MAIL_DEBUG'] = 
app.config['MAIL_USERNAME'] = 'no.reply1720@gmail.com'
app.config['MAIL_PASSWORD'] = 'sanmoy20'
app.config['MAIL_DEFAULT_SENDER'] = 'no.reply1720@gmail.com'
app.config['MAIL_MAX_EMAILS'] = None
#app.config['MAIL_SUPPRESS_SEND'] = False
app.config['MAIL_ASCII_ATTACHMENTS'] = False
app.config['GOOGLE_ID'] = "97700423682-vs263g2opsvbbeeq10pr57qbtqcc2e37.apps.googleusercontent.com"
app.config['GOOGLE_SECRET'] = "cfYJjgV3MOWsoEXdwKKfU2gh"
app.debug = True
app.secret_key = 'development'
oauth = OAuth(app)

mail = Mail(app)
s = URLSafeTimedSerializer('thisisseccret!')
conn = sqlite3.connect('C:/sqlite/test.db', check_same_thread=False)
totp = pyotp.TOTP('base32secret3232')
#app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:////C:/sqlite/test.db"
#db = SQLAlchemy(app)
#login_manager = LoginManager()
#login_manager.init_app(app)

@app.route('/admin/signup', methods=['GET'])
@cross_origin(origin='*') 
def renderAdminRegisterPage():
#    return render_template('register.html')
    resp = make_response(render_template('register.html'))
    resp.set_cookie('portaregisteradmin', 'thisisasecretadminregister', max_age=60*60*24*365*2)
    return resp 

@app.route('/api/v1/admin/otpvalidation/<usrid>', methods=['GET'])
@cross_origin(origin='*') 
def renderOTPPage(usrid):
#    return render_template('otpValidation.html')
    resp = make_response(render_template('otpValidation.html'))
    resp.set_cookie('portaotp', 'thisisasecretotpvalidation', max_age=60*60*24*365*2)
    return resp 

@app.route('/admin/forgotPassword', methods=['GET'])
def adminRenderForgotPwdPage():  
    return render_template('forgotPassword.html')

@app.route('/admin/forgotPassword/<userid>', methods=['GET'])
def adminRenderPwdChangePage(userid):  
    return render_template('changePassword.html')

@app.route('/admin/profile', methods=['GET'])
def adminProfile():  
    return render_template('admin_v2.html')
#    resp = make_response(render_template('admin_v2.html'))
#    resp.set_cookie('portaadminlogin', 'thisisasecretotpvalidation', max_age=60*60)
#    return resp 
    
@app.route('/admin/logout', methods=['GET'])
@cross_origin(origin='*', headers=["Content-Type", "EMAILID", "USERID"])       
def adminLogout():
    print("adminLogout==================")
    session['user_id'] = None
    return redirect(url_for("adminLogin"))
#       logout_user()

@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session and request.endpoint=='adminProfile':
        usrArr = checkUser('ADMIN', session['user_id'], None)
        if usrArr:
            print("in usrrrrrrrrrrrrrrrrrrrr")
            print(usrArr[0])
            regdt = datetime.datetime.strptime(usrArr[0]["REGDT"], '%Y-%m-%d %H:%M:%S')
            lastLoginDT = datetime.datetime.strptime(usrArr[0]["LAST_LOGINDT"], '%Y-%m-%d %H:%M:%S')
            usrArr[0]["REGDT"] = regdt.strftime("%B %d, %Y")
            usrArr[0]["LAST_LOGINDT"] = lastLoginDT.strftime("%B %d, %Y, %H:%M:%S")
            g.user = usrArr[0]
        else:
            return jsonify({"error": "Internal Server Error"})
        
@app.route('/admin/login', methods=['GET', 'POST'])
@cross_origin(origin='*', headers=["Content-Type", "signInType"]) 
def adminLogin():
    if request.method == "POST":
        if "multipart/form-data" in request.headers["Content-Type"]:
            print("Post of Admin Login===============")
            print(request.headers["signInType"])
            loginDetails = json.loads(request.form['data'])
            emailid = loginDetails['emailid']
            usrArr = checkUser('ADMIN', emailid, None)
            if len(usrArr)>0:
                cur = conn.cursor()
#                userid = usrArr[0]["USERID"]
                loginTime = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d %H:%M:%S')
                usrtype='ADMIN'
                session.pop('user_id', None)
                if usrArr[0]["STATUS"]:
                    if request.headers["signInType"] == 'google':
                        session['user_id'] = emailid
                        cur.execute("UPDATE S_USER_MASTER SET LAST_LOGINDT='"+loginTime+"'"+"WHERE USERTYPE='"+usrtype+"'"+"AND EMAILID='"+emailid+"'")
                        conn.commit()
                        return jsonify({"message": "User loggedin", "url": url_for('adminProfile', _external=True)}), 200
#                        return redirect(url_for("adminProfile"))
                    else:
                        password = loginDetails['password']
                        cur = conn.cursor()
                        row = cur.execute("SELECT * FROM S_REGISTER_ADMIN where EMAILID ='"+emailid+"'")
                        for row in cur:
                            if row[5]==password:
                                session['user_id'] = emailid
#                                login_user(usrArr[0])
                                cur.execute("UPDATE S_USER_MASTER SET LAST_LOGINDT='"+loginTime+"'"+"WHERE USERTYPE='"+usrtype+"'"+"AND EMAILID='"+emailid+"'")
                                conn.commit()
                                return jsonify({"message": "User loggedin", "url": url_for('adminProfile', _external=True)}), 200
#                                return redirect(url_for("adminProfile"))
                            else:
                                return jsonify({"error": "Invalid password"}), 400
                                
                else:
                    #flash('User not activated', 'danger')
                    return jsonify({"error": "User not activated"}), 400
            else:
                return jsonify({"error": "Invalid User"}), 400
        else:
            return jsonify({"error": "Missing [Content-Type]"}), 400   
    else:
        return render_template("login.html")        
        
        

@app.route('/api/v1/admin/forgotPassword', methods=['POST'])
@cross_origin(origin='*',headers=['Content-Type'])
def forgotPassword():
    print("forgotPassword------------------")
    try:
        if "multipart/form-data" in request.headers["Content-Type"]:
            pwdDetails = json.loads(request.form['data'])
            userid = pwdDetails['userid']
            pwd = pwdDetails['pwd']
            cur = conn.cursor()
            row = cur.execute("SELECT * FROM S_REGISTER_ADMIN where ADMINID ='"+userid+"'")
            row = cur.fetchone()
            if row:
                cur.execute("UPDATE S_REGISTER_ADMIN SET PWD='"+pwd+"'"+"WHERE ADMINID='"+userid+"'"+"AND EMAILID='"+row[2]+"'")
                conn.commit()
#                return redirect(url_for("adminLogin"))
                return jsonify({"message": "Password Changed successfully", "userid": userid}), 200
            else:
                return jsonify({"error": "Invalid User"}), 400
        else:
            return jsonify({"error": "Invalid ['Content-Type']"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/admin/changepassword', methods=['POST'])
@cross_origin(origin='*',headers=['Content-Type'])
def changePassword():
    print("changePassword------------------")
    try:
        if "multipart/form-data" in request.headers["Content-Type"]:
            pwdDetails = json.loads(request.form['data'])
            userid = pwdDetails['userid']
            oldPwd = pwdDetails['oldpwd']
            pwd = pwdDetails['pwd']
            cur = conn.cursor()
            row = cur.execute("SELECT * FROM S_REGISTER_ADMIN where ADMINID ='"+userid+"'")
            row = cur.fetchone()
            if row:
                if row[5] == oldPwd:
                    if pwd != oldPwd:
                        cur.execute("UPDATE S_REGISTER_ADMIN SET PWD='"+pwd+"'"+"WHERE ADMINID='"+userid+"'"+"AND EMAILID='"+row[2]+"'")
                        conn.commit()
                        return jsonify({"message": "Password Changed successfully", "userid": userid}), 200
                    else:
                        return jsonify({"error": "Old Password and New Password cannot be same"}), 400
                else:
                    return jsonify({"error": "Old Password didnot match"}), 400
            else:
                return jsonify({"error": "Invalid User"}), 400
        else:
            return jsonify({"error": "Invalid ['Content-Type']"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500        

@app.route('/api/v1/admin/register', methods=['POST'])
@cross_origin(origin='*',headers=['Content-Type'])
def registerAdmin():
    try:
        if "multipart/form-data" in request.headers["Content-Type"]:
#        if request.method == 'POST':
            print("in registerAdmin===================")
            print(request.form['data'])
            adminDetails = json.loads(request.form['data'])
            print(adminDetails)
            print(adminDetails["name"])
            name = adminDetails['name']
            phNo = adminDetails['phNo']
            emailid = adminDetails['emailid']
            adminid = "A"+str(uuid.uuid4())[:8]
            pwd = adminDetails['pwd']
            dob = adminDetails['dob']
            reg_dt = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d %H:%M:%S')
            adminStatus = False
            cur = conn.cursor()
            email = cur.execute("SELECT EMAILID FROM S_REGISTER_ADMIN where EMAILID ='"+emailid+"'")
            email = cur.fetchone()
            print("print EMAILID=================")
            print(email)
            if email:
                #flash('Emailid already exists', 'danger')
                return jsonify({"error": "Emailid already exists"}), 400
            else:
                phno = cur.execute("SELECT PHNO FROM S_REGISTER_ADMIN where PHNO ='"+phNo+"'")
                phno = cur.fetchone()
                if phno:
                    #flash('PhNo already exists', 'danger')
                    return jsonify({"error": "PhNo already exists"}), 400
                else:
#                    OTP = totp.now()
                    OTP = 57859
#                    resp = send_sms_email.sendOTP_SMS(phNo, OTP)
                    resp = dict()
                    resp["return"]= True
                    if resp["return"]:
                        usrObj = dict()
                        usrObj["Name"] = name
                        usrObj["PhNo"] = phNo
                        usrObj["EmailID"] = emailid
                        usrObj["AdminID"] = adminid
                        usrObj["DOB"] = dob
                        usrObj["REG_DT"] = reg_dt
                        usrObj["Status"] = adminStatus
                        cur.execute("INSERT INTO S_OTP_VALIDATION(ID, OTP) VALUES(?,?)", (adminid, OTP))
                        cur.execute("INSERT INTO S_REGISTER_ADMIN(ADMINID, NAME, STATUS, EMAILID, PWD, REG_DT, PHNO, DOB) VALUES(?,?,?,?,?,?,?,?)", (adminid, name, adminStatus, emailid, pwd, reg_dt, phNo, dob))
                        cur.execute("INSERT INTO S_USER_MASTER(USERID, USERTYPE, USERNAME, EMAILID, REGDT, USERSTATUS) VALUES(?,?,?,?,?,?)", (adminid, 'ADMIN', name, emailid, reg_dt, adminStatus))
                        conn.commit()
                        return jsonify(usrObj), 200
#                       cur.execute("INSERT INTO S_REGISTER_CUST(CUSTID, NAME, PHNO, EMAILID, ADDRESS) VALUES(%s, %s, %s, %s, %s)", (custid, name, phNo, emailid, addr))
#                       return render_template('otpValidation.html', data=adminid)
                    else:
#                        flash('Internal Server Error', 'danger')
                       return jsonify({"error": "Internal Server Error"}), 500
        else:
            return jsonify({"error": "Invalid ['Content-Type']"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 400
#        flash(str(e), 'danger')
 
#@app.route('/api/v1/check/user/<usertype>', methods=['GET'])
#@cross_origin(origin='*',headers=['Content-Type', 'EMAILID'])   
def checkUser(usrtype, emailid, pwd):
    print("=============FUNC checkGoogleUser===============")
    print(usrtype)
    print(emailid)
    cur = conn.cursor()
    row = cur.execute("SELECT * FROM S_USER_MASTER where EMAILID ='"+emailid+"' AND USERTYPE='"+usrtype.upper()+"'")
    usrArr = list()
    for row in cur:
        rowObj = dict()
        rowObj['USERID'] = row[0]
        rowObj['USERTYPE'] = row[1]
        rowObj['USERNAME'] = row[2]
        rowObj['EMAILID'] = row[3]
        rowObj['REGDT'] = row[4]
        rowObj['STATUS'] = row[5]
        rowObj['LAST_LOGINDT'] = row[6]
        usrArr.append(rowObj)
    return usrArr
   
    
#@app.route('/api/v1/login/admin', methods=['GET'])
#@cross_origin(origin='*',headers=['Content-Type'])    
#def loginAdminUser(emailid):
#    cur = conn.cursor()
#    row = cur.execute("SELECT * FROM S_USER_MASTER where EMAILID ='"+emailid+"'")
#    print(row)
#    if len(row)>0:
#        response = Response(
#            response=json.dumps(row[0]),
#            status=200,
#            mimetype='application/json'
#        )
#        return response
#    else:
#        return 'Not found', 404

        

    
@cross_origin(origin='*',headers=['Content-Type', 'Authorization'])
def registerServiceProvider():
    try:
        if "multipart/form-data" in request.headers["Content-Type"]:
            adminDetails = request.form
            name = adminDetails['name']
            phNo = adminDetails['phNo']
            emailid = adminDetails['emailid']
            addr = adminDetails['addr']
            sellerID = "S"+str(uuid.uuid4())[:8]
            pwd = adminDetails['pwd']
            reg_dt = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d %H:%M:%S')
            sellerStatus = False
            cur = conn.cursor()
            emailExists = cur.execute("SELECT * FROM S_REGISTER_SELLER where EMAILID ='"+emailid+"'")
            phNoExists = cur.execute("SELECT * FROM S_REGISTER_SELLER where PHNO ='"+phNo+"'")
            if int(emailExists) > 0:
                return jsonify({"error": "Emailid already exists"}), 400
            elif int(phNoExists)>0:
                return jsonify({"error": "PhNo already exists"}), 400
            else:
                OTP = totp.now()
                resp = send_sms_email.sendOTP_SMS(phNo, OTP)
                if resp["return"]:
                    cur.execute("INSERT INTO S_OTP_VALIDATION(ID, OTP) VALUES(?,?)", (sellerID, OTP))
#                cur.execute("INSERT INTO S_REGISTER_CUST(CUSTID, NAME, PHNO, EMAILID, ADDRESS) VALUES(%s, %s, %s, %s, %s)", (custid, name, phNo, emailid, addr))
                    cur.execute("INSERT INTO S_REGISTER_SELLER(CUSTID, NAME, PHNO, EMAILID, ADDRESS, CUST_STATUS, PWD, REG_DT) VALUES(?,?,?,?,?,?,?)", (sellerID, name, phNo, emailid, addr, sellerStatus, pwd, reg_dt))
                    cur.execute("INSERT INTO S_USER_MASTER(USERID, USERTYPE, EMAILID, USERSTATUS) VALUES(?,?,?,?)", (sellerID, 'SELLER', emailid, sellerStatus))
                    conn.commit()
                return jsonify({"status": "created"}), 200
        else:
            raise BadRequest()
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/v1/custregister', methods=['POST'])
@cross_origin(origin='*',headers=['Content-Type'])
def registerCustomer():
    print("======registerCustomer========")
    try:
        if "multipart/form-data" in request.headers["Content-Type"]:
            custDetails = request.form
            name = custDetails['name']
            phNo = custDetails['phNo']
            emailid = custDetails['emailid']
            addr = custDetails['addr']
            custid = "C"+str(uuid.uuid4())[:8]
            pwd = custDetails['pwd']
            reg_dt = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d %H:%M:%S')
            custStatus = False
            cur = conn.cursor()
            emailExists = cur.execute("SELECT * FROM S_REGISTER_CUST where EMAILID ='"+emailid+"'")
            phNoExists = cur.execute("SELECT * FROM S_REGISTER_CUST where PHNO ='"+phNo+"'")
            if int(emailExists) > 0:
                return jsonify({"error": "Emailid already exists"}), 400
            elif int(phNoExists)>0:
                return jsonify({"error": "PhNo already exists"}), 400
            else:
                OTP = totp.now()
                resp = send_sms_email.sendOTP_SMS(phNo, OTP)
                if resp["return"]:
                    cur.execute("INSERT INTO S_OTP_VALIDATION(ID, OTP) VALUES(?,?)", (custid, OTP))
    #                cur.execute("INSERT INTO S_REGISTER_CUST(CUSTID, NAME, PHNO, EMAILID, ADDRESS) VALUES(%s, %s, %s, %s, %s)", (custid, name, phNo, emailid, addr))
                    cur.execute("INSERT INTO S_REGISTER_CUST(CUSTID, NAME, GENDER, PHNO, EMAILID, ADDRESS, CUST_STATUS, PWD, REG_DT) VALUES(?,?,?,?,?,?,?,?,?,?)", (custid, name, phNo, emailid, addr, custStatus, pwd, reg_dt))
                    
                    conn.commit()
                    return jsonify({"status": "created", "CUSTID":custid, "OTP":OTP, "Active":False}), 200
                else:
                    return jsonify({"error": resp["message"]}), 400
        else:
            raise BadRequest()
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    
@app.route('/api/v1/user/activate/<otp>', methods=['GET'])
@cross_origin(origin='*',headers=['Content-Type', "ID"])
def activateUser(otp):
    print("==========activate user================")
    userid = request.headers['ID']
    userCode = userid[:1]
    print(userid)
    print(userCode)
    print("fetch otp=================")
    cur = conn.cursor()
    cur.execute("SELECT OTP FROM S_OTP_VALIDATION where ID = '"+userid+"'")
    row = cur.fetchone()
    print("print=================")
    print(row[0])
    email = ""
    if row[0]:
        if row[0]==otp:
            cur.execute("UPDATE S_USER_MASTER SET USERSTATUS=True where USERID='"+userid+"'")
            if userCode == 'C':
                cur.execute("UPDATE S_REGISTER_CUST SET CUST_STATUS=True where CUSTID='"+userid+"'")
                email = cur.execute("SELECT EMAILID FROM S_REGISTER_CUST where CUSTID='"+userid+"'")
                email = cur.fetchone()
                print("print email in activate=================")
                print(email[0])
                sendActivationEMAIL(email[0], 'adminLogin')
            if userCode == 'A':
                cur.execute("UPDATE S_REGISTER_ADMIN SET STATUS=True where ADMINID='"+userid+"'")
                email = cur.execute("SELECT EMAILID FROM S_REGISTER_ADMIN where ADMINID='"+userid+"'")
                email = cur.fetchone()
                print("print email in activate=================")
                print(email[0])
                sendActivationEMAIL(email[0], 'adminLogin')
            else:
                print("Customer no found")
            cur.execute("DELETE FROM S_OTP_VALIDATION where ID ='"+userid+"'")
            conn.commit()
        else:
            return jsonify({"error": "OTP did not match"}), 400
        msg = "User: "+userid+" has been activated"
        return jsonify({"message":msg}), 200
    else:
        return jsonify({"error": "User does not exists"}), 400
    


@app.route('/api/v1/allcust', methods=['GET'])
@cross_origin(origin='*',headers=['Content-Type'])
def getAllCustomers():
    try:
        if "application/json" in request.headers["Content-Type"]:
            cur = conn.cursor()
            cur.execute("SELECT * FROM S_REGISTER_CUST")
            data = cur.fetchall()
            if not data:
                return 'No Data', 404
            else:
                response = Response(
                    response=json.dumps(data),
                    status=200,
                    mimetype='application/json'
                )
                return response
        else:
            raise BadRequest()
    except Exception as e:
        return jsonify({"error": str(e)}), 400
        


@app.route('/api/v1/customer/search', methods=['GET'])
@cross_origin(origin='*',headers=['Content-Type'])
def custSearch():
    print("==========getCustByID================")
    key = list(dict(request.args).keys())[0]
    value = list(dict(request.args).values())[0]
    cur = conn.cursor()
    cur.execute("SELECT * FROM S_REGISTER_CUST where "+key+"='"+value+"'")
    custArr = list()
    for row in cur:
        rowObj = dict()
        rowObj['CUSTID'] = row[0]
        rowObj['NAME'] = row[1]
        rowObj['PHNO'] = row[2]
        rowObj['EMAILID'] = row[3]
        rowObj['ADDRESS'] = row[4]
        rowObj['CUST_STATUS'] = row[5]
        custArr.append(rowObj)
    if len(custArr)>0:
        response = Response(
            response=json.dumps(custArr),
            status=200,
            mimetype='application/json'
        )
        return response
    else:
        return 'Not found', 404

@app.route('/api/v1/customer/<custid>', methods=['DELETE'])
@cross_origin(origin='*',headers=['Content-Type'])
def deleteCust(custid):
    print("==========deleteCust================")
    cur = conn.cursor()
    cur.execute("DELETE FROM S_REGISTER_CUST where CUSTID ='"+custid+"'")
    conn.commit()
    respObj = dict()
    respObj['CUSTID'] = custid
    respObj['STATUS'] = 'DELETED'
    response = Response(
        response=json.dumps(respObj),
        status=200,
        mimetype='application/json'
    )
    return response

@app.route('/api/v1/account/activate/<emailid>', methods=['GET'])
def sendActivationEMAIL(emailid, url):
    print("==========sendActivationEMAIL================")
#    emailid = request.headers['EMAILID']
    print(emailid)
#    token = s.dumps(emailid, salt='email-confirm')
#    link = url_for('confirm_email', token=token, _external=True)
    link = url_for(url, _external=True)
    print(link)
    subject = "Account activated"
    msgBody = "Login to continue {}".format(link)
    msg = send_sms_email.sendEMAIL(app, emailid, subject, msgBody)
    response = Response(
        response=json.dumps({"message":msg}),
        status=200,
        mimetype='application/json'
    )
    return response

#@app.route('/api/v1/confirm_email/<token>', methods=['GET'])
#@cross_origin(origin='*', headers=['Content-Type', "EMAILID"])
#def confirmEMAIL(token):
#    try:
#        email = s.loads(token, salt='email-confirm', max_age=300)
#    except SignatureExpired:
#        return '<h1> The token is expired</h1>'
    






if __name__=='__main__':
    app.secret_key = 'super secret key'
    app.config['SESSION_TYPE'] = 'filesystem'
    app.run(debug=True)





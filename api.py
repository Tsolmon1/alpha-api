from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt, time, json
import datetime
from functools import wraps
from flask_migrate import Migrate
from flask_login import UserMixin

from datetime import date

#app.config['SECRET_KEY'] = 'thisissecret'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/python_projects/api_example/loan.db'

app = Flask(__name__, instance_relative_config=True)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config.from_pyfile('config.py')
app.config["DEBUG"] = True
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    full_name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    register_number = db.Column(db.String(50), unique=True)
    phone_number = db.Column(db.Integer, unique=True)
    civil_number = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(80))
    address = db.Column(db.String(120))
    secure_question = db.Column(db.String(120))
    relate_phone = db.Column(db.Integer, unique=True)
    married = db.Column(db.Boolean)
    withlive = db.Column(db.String(80))
    home_income = db.Column(db.Integer)
    home_member_income = db.Column(db.Integer)
    educational_level = db.Column(db.String(80))
    is_job = db.Column(db.Boolean)
    company_name = db.Column(db.String(80))
    social_insurance = db.Column(db.Boolean)
    this_company_worked_year = db.Column(db.Integer)
    worked_organ_number = db.Column(db.Integer)
    fb_or_email_connect = db.Column(db.Boolean)
    income_source = db.Column(db.String(80))
    month_income = db.Column(db.Integer)
    is_before_loan = db.Column(db.Boolean)
    is_activate_loan = db.Column(db.Boolean)
    total_activate_loan = db.Column(db.Integer)
    internet_account_code = db.Column(db.Integer)
    download_loan_db_perm = db.Column(db.Boolean)
    location_perm = db.Column(db.Boolean)
    download_data_phone_perm = db.Column(db.Boolean)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.datetime.utcnow)

class Loan_log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    loan_request_id = db.Column(db.Integer, db.ForeignKey('loan_requests.id'), index=True)
    start_date = db.Column(db.DateTime, index=True)
    due_date = db.Column(db.DateTime, index=True)
    note = db.Column(db.String(60), index=True)

class Loan_request(db.Model):

    __tablename__ = 'loan_requests'
    id = db.Column(db.Integer, primary_key=True)
   # recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    approved = db.Column(db.Boolean)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    loan_type_id = db.Column(db.Integer, db.ForeignKey('loan_types.id'))
    amount = db.Column(db.Integer)
    days = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.datetime.utcnow)
    cancel = db.Column(db.Integer, default=0)
    close = db.Column(db.Integer, default=0)
    comments = db.relationship('Comment', backref='loan_request',
                                    lazy='dynamic')
    def __repr__(self):
        return '<Loan_request {}>'.format(self.amount)

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
   
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'))
    loan_request_id = db.Column(db.Integer, db.ForeignKey('loan_requests.id'))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.datetime.utcnow)
    text = db.Column(db.Text)
    
    def __repr__(self):
        return '<Comment {}>'.format(self.text)

class Close(db.Model):
    __tablename__ = 'closes'
    id = db.Column(db.Integer, primary_key=True)   
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'))
    loan_request_id = db.Column(db.Integer, db.ForeignKey('loan_requests.id'))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.datetime.utcnow)
    text = db.Column(db.String(120))
    
    def __repr__(self):
        return '<Comment {}>'.format(self.text)

class Employee(UserMixin, db.Model):
    """
    Create an Employee table
    """

    # Ensures table will be named in plural and not in singular
    # as is the name of the model
    __tablename__ = 'employees'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(60), index=True, unique=True)
    username = db.Column(db.String(60), index=True, unique=True)
    first_name = db.Column(db.String(60), index=True)
    last_name = db.Column(db.String(60), index=True)
    password_hash = db.Column(db.String(128)) 
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    is_admin = db.Column(db.Boolean, default=False)


    last_message_read_time = db.Column(db.DateTime)
    comments = db.relationship('Comment', backref='employee',
                                    lazy='dynamic')


    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, current_app.config['SECRET_KEY'],
                            algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)
    


    @property
    def password(self):
        """
        Prevent pasword from being accessed
        """
        raise AttributeError('password is not a readable attribute.')

    @password.setter
    def password(self, password):
        """
        Set password to a hashed password
        """
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        """
        Check if hashed password matches actual password
        """
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<Employee: {}>'.format(self.username)
    

    
  

class Role(db.Model):
    """
    Create a Role table
    """

    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60), unique=True)
    description = db.Column(db.String(200))
    employees = db.relationship('Employee', backref='role',
                                lazy='dynamic')

    def __repr__(self):
        return '<Role: {}>'.format(self.name)

class Loan_type(db.Model):
    """
    Create an Employee table
    """

    # Ensures table will be named in plural and not in singular
    # as is the name of the model
    __tablename__ = 'loan_types'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60), index=True, unique=True)
    amount_from = db.Column(db.Integer, index=True)
    amount_to = db.Column(db.Integer, index=True)
    days_from = db.Column(db.Integer, index=True)
    days_to = db.Column(db.Integer) 
    date_from = db.Column(db.DateTime)
    date_to = db.Column(db.DateTime)
    interest_rate = db.Column(db.Integer)
    interest_type = db.Column(db.String(60), index=True)
    loan_requests = db.relationship('Loan_request', backref='loan_type', 
                                lazy='dynamic')
    def __repr__(self):
            return '<Loan_type {}>'.format(self.name)

class Loan_capacity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    account_limit = db.Column(db.Integer, index=True)
    date_from = db.Column(db.DateTime, index=True)
    date_to = db.Column(db.DateTime, index=True)

    def __repr__(self):
            return '<Loan_capacity {}>'.format(self.account_limit)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated


@app.route('/user', methods=['GET'] )
@token_required
def get_all_user(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})
    users = User.query.all()
    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['full_name'] = user.full_name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        user_data['register_number'] = user.register_number
        user_data['phone_number'] = user.phone_number
        user_data['civil_number'] = user.civil_number
        user_data['email'] = user.email
        user_data['address'] = user.address
        user_data['secure_question'] = user.secure_question
        user_data['relate_phone'] = user.relate_phone
        user_data['married'] = user.married
        user_data['withlive'] = user.withlive
        user_data['home_income'] = user.home_income
        user_data['home_member_income'] = user.home_member_income
        user_data['educational_level'] = user.educational_level
        user_data['is_job'] = user.is_job
        user_data['company_name'] = user.company_name
        user_data['social_insurance'] = user.social_insurance
        user_data['this_company_worked_year'] = user.this_company_worked_year
        user_data['worked_organ_number'] = user.worked_organ_number
        user_data['fb_or_email_connect'] = user.fb_or_email_connect
        user_data['income_source'] = user.income_source
        user_data['month_income'] = user.month_income
        user_data['is_before_loan'] = user.is_before_loan
        user_data['is_activate_loan'] = user.is_activate_loan
        user_data['total_activate_loan'] = user.total_activate_loan
        user_data['internet_account_code'] = user.internet_account_code
        user_data['download_loan_db_perm'] = user.download_loan_db_perm
        user_data['location_perm'] = user.location_perm
        user_data['download_data_phone_perm'] = user.download_data_phone_perm

        output.append(user_data)
    return jsonify({'users' : output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message' : 'No user found!'})
    
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['full_name'] = user.full_name
    user_data['password'] = user.password
    user_data['admin'] = user.admin
    user_data['register_number'] = user.register_number
    user_data['phone_number'] = user.phone_number
    user_data['civil_number'] = user.civil_number
    user_data['email'] = user.email
    user_data['address'] = user.address
    user_data['secure_question'] = user.secure_question
    user_data['relate_phone'] = user.relate_phone
    user_data['married'] = user.married
    user_data['withlive'] = user.withlive
    user_data['home_income'] = user.home_income
    user_data['home_member_income'] = user.home_member_income
    user_data['educational_level'] = user.educational_level
    user_data['is_job'] = user.is_job
    user_data['company_name'] = user.company_name
    user_data['social_insurance'] = user.social_insurance
    user_data['this_company_worked_year'] = user.this_company_worked_year
    user_data['worked_organ_number'] = user.worked_organ_number
    user_data['fb_or_email_connect'] = user.fb_or_email_connect
    user_data['income_source'] = user.income_source
    user_data['month_income'] = user.month_income
    user_data['is_before_loan'] = user.is_before_loan
    user_data['is_activate_loan'] = user.is_activate_loan
    user_data['total_activate_loan'] = user.total_activate_loan
    user_data['internet_account_code'] = user.internet_account_code
    user_data['download_loan_db_perm'] = user.download_loan_db_perm
    user_data['location_perm'] = user.location_perm
    user_data['download_data_phone_perm'] = user.download_data_phone_perm

    return jsonify({'user' : user_data})

@app.route('/user', methods=['POST'])

def create_user():

    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), full_name=data['full_name'], password=hashed_password, admin=False, register_number=data['register_number'], phone_number=data['phone_number'], civil_number=data['civil_number'], email=data['email'], address=data['address'], secure_question=data['secure_question'], relate_phone=data['relate_phone'], married=data['married'], withlive=data['withlive'], home_income=data['home_income'], home_member_income=data['home_member_income'], educational_level=data['educational_level'], is_job=data['is_job'], company_name=data['company_name'], social_insurance=data['social_insurance'], this_company_worked_year=data['this_company_worked_year'], worked_organ_number=data['worked_organ_number'], fb_or_email_connect = data['fb_or_email_connect'], income_source = data['income_source'], month_income = data['month_income'], is_before_loan = data['is_before_loan'], is_activate_loan = data['is_activate_loan'], total_activate_loan = data ['total_activate_loan'], internet_account_code = data['internet_account_code'], download_loan_db_perm = data ['download_loan_db_perm'], location_perm = data['location_perm'], download_data_phone_perm = data['download_data_phone_perm'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message' : 'New user created!'})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
       return jsonify({'message' : 'Cannot perform that function!'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message' : 'No user found!'})
    user.admin = True
    db.session.commit()
    return jsonify({'message' : 'The user has been promoted!'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
         return jsonify({'message' : 'Cannot perform that function!'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message' : 'No user found!'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message' : 'The user has been deleted!'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(full_name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8')})
    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

@app.route('/loan_request', methods=['GET'])
@token_required
def get_all_loan_requests(current_user):
    loan_requests = Loan_request.query.filter_by(user_id=current_user.id).all()

    output = []
    for loan_request in loan_requests:
        loan_request_data = {}
        loan_request_data['id'] = loan_request.id
        loan_request_data['amount'] = loan_request.amount
        loan_request_data['days'] = loan_request.days
        loan_request_data['approved'] = loan_request.approved
        loan_request_data['loan_type_id'] = loan_request.loan_type_id
        output.append(loan_request_data)

    return jsonify({'loan_requests' : output})

@app.route('/loan_request/<loan_request_id>', methods=['GET'])
@token_required
def get_one_loan_request(current_user, loan_request_id):
    loan_request = Loan_request.query.filter_by(id=loan_request_id, user_id=current_user.id).first()

    if not loan_request:
        return jsonify({'message' : 'No loan_request found!'})
    loan_request_data = {}
    loan_request_data['id'] = loan_request.id
    loan_request_data['amount'] = loan_request.amount
    loan_request_data['days'] = loan_request.days
    loan_request_data['approved'] = loan_request.approved
    loan_request_data['loan_type_id'] = loan_request.loan_type_id

    return jsonify(loan_request_data)

@app.route('/loan_request', methods=['POST'])
@token_required
def create_loan_request(current_user):
    data = request.get_json()
    new_loan_request = Loan_request(amount=data['amount'], days=data['days'], approved=False, user_id=current_user.id, loan_type_id=data['loan_type_id'])
    db.session.add(new_loan_request)
    db.session.commit()
    return jsonify({'message' : "Loan request created!"})

@app.route('/loan_request/<loan_request_id>', methods=['PUT'])
@token_required
def approved_loan_request(current_user, loan_request_id):
    loan_request = Loan_request.query.filter_by(id=loan_request_id, user_id=current_user.id).first()

    if not loan_request:
        return jsonify({'message' : 'No loan_request found!'})
    
    loan_request.approved = True
    db.session.commit()

    return jsonify({'message' : 'Loan request item has been approved!'})

@app.route('/loan_request/<loan_request_id>', methods=['DELETE'])
@token_required
def delete_loan_request(current_user, loan_request_id):
    loan_request = Loan_request.query.filter_by(id=loan_request_id, user_id=current_user.id).first()

    if not loan_request:
        return jsonify({'message' : 'No loan_request found!'})
    db.session.delete(loan_request)
    db.session.commit()
    return jsonify({'message' : 'Loan request item deleted!'})

if __name__ == '__main__':
    app.run(debug=True)
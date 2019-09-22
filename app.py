from flask import Flask, render_template, request,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_paginate import Pagination, get_page_args
from flask_jwt import JWT, jwt_required, current_identity
from werkzeug.security import safe_str_cmp
from flask_bcrypt import Bcrypt
from flask_restful import Api, Resource, fields, marshal_with



#----------------------------------------------------------------------

app = Flask(__name__)
bcrypt = Bcrypt(app)
api = Api(app)
app.template_folder = ''
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://ujwqfzaukxlmoa:e8f64d125e4527f97c0d06d00d752cdb6c01befe518d9de8db69dd650dca356f@ec2-107-20-167-241.compute-1.amazonaws.com:5432/d8844vj4iesqq3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'Ill never tell'
db = SQLAlchemy(app)
db.Model.metadata.reflect(db.engine)

#---------------------------------------------------------------

class User(db.Model):
	__table__ = db.Model.metadata.tables['users']
	
	def __init__(self, id, username, password):
		self.id = id 
		self.username = username
		self.password = bcrypt.generate_password_hash(password).decode('UTF-8')

user_fields = {
    'id': fields.Integer,
    'username': fields.String
}



class banks(db.Model):
	banks = db.Model.metadata.tables['banks']

	def __repr__(self):
	    return self.id	

class branches(db.Model):
	branches = db.Model.metadata.tables['branches']

	def __repr__(self):
	    return self.bank_id	



@api.resource('/users')
class UserListAPI(Resource):
    @marshal_with(user_fields)
    def get(self):
        return User.query.all()

    @marshal_with(user_fields)
    def post(self):
        new_user = User(request.json['id'],request.json['username'],request.json['password'])
        db.session.add(new_user)
        db.session.commit()
        return new_user

@api.resource('/users/<id>')
class UserAPI(Resource):
    @marshal_with(user_fields)
    @jwt_required()
    def get(self,id):
        return current_identity

    @marshal_with(user_fields)
    @jwt_required()
    def patch(self,id):
        current_identity.username = request.json['username']
        current_identity.password = bcrypt.generate_password_hash(request.json['password']).decode('UTF-8')
        db.session.add(current_identity)
        db.session.commit()
        return current_identity



def authenticate(username, password):
    user = User.query.filter(User.username == username).first()
    if bcrypt.check_password_hash(user.password, password):
        return user	



#/////////////////////////////////////////////////////////////

@app.route('/protected')
@jwt_required()
def protected():
    return '%s' % current_identity


@app.route('/branches/<ifsc>', methods=['GET', 'POST'])
@jwt_required()
def branch_details(ifsc):
	if request.method == 'GET':
		temp2 = []
		r = branches.query.filter_by(ifsc=ifsc).first()
		p = banks.query.filter_by(id = r.bank_id).first()
		a = {"ifsc": r.ifsc, "bank_id": r.bank_id, "bank_name":p.name, "branch": r.branch, "address":r.address, "city":r.city, "district":r.district, "state":r.state}  
		temp2.append(a)  
		
		return render_template('branches_get.html',
							passer = temp2)


@app.route('/bank_details/<bank_name>/<city>', methods=['GET', 'POST']) 
@jwt_required()
def bank_details(bank_name, city):
	if request.method == 'GET':
		get_bank_details = banks.query.filter_by(name=bank_name).first()
		r1 = branches.query.filter_by( bank_id = get_bank_details.id).filter_by(city = city)
		page = int(request.args.get('page', 1))
		per_page = 10
		offset = (page - 1) * per_page
		files_for_render = r1.limit(per_page).offset(offset)
		search = False
		q = request.args.get('q')
		if q:
			search = True

		pagination = Pagination(page=page, per_page=per_page, offset=offset,
                           total=r1.count(), css_framework='bootstrap4', 
                           search=search)
	return render_template('index.html',
                           passer=files_for_render,
						   bank_name = get_bank_details.name,
                           page=page,
                           per_page=per_page,
                           pagination=pagination
                           )



def identity(payload):
    user_id = payload['identity']
    return User.query.get(user_id)



jwt = JWT(app, authenticate, identity)

if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from marshmallow import Schema, fields, ValidationError
from bson import ObjectId
from dotenv import load_dotenv
from os import getenv

load_dotenv()


app = Flask(__name__)

app.config["MONGO_URI"] = getenv("MONGODB_URL")
mongo = PyMongo(app)

app.config["JWT_SECRET_KEY"] = getenv("JWT_SECRET")
jwt = JWTManager(app)

class UserSchema(Schema):
    first_name = fields.Str(required=True)
    last_name = fields.Str(required=True)
    email = fields.Email(required=True)
    password = fields.Str(required=True)

user_schema = UserSchema()

class TemplateSchema(Schema):
    template_name = fields.Str(required=True)
    subject = fields.Str(required=True)
    body = fields.Str(required=True)

template_schema = TemplateSchema()

@app.route('/register', methods=['POST'])
def register():
    try:
        user_data = user_schema.load(request.get_json())
    except ValidationError as error:
        return jsonify(error.messages), 400

    existing_user = mongo.db.users.find_one({"email": user_data["email"]})
    if existing_user:
        return jsonify({"message": "User already exists"}), 400

    user_data["password"] = generate_password_hash(user_data["password"])
    mongo.db.users.insert_one(user_data)

    return jsonify({"message": "Registration successful"}), 201

@app.route('/login', methods=['POST'])
def login():
    credentials = request.get_json()
    user = mongo.db.users.find_one({"email": credentials["email"]})

    if not user or not check_password_hash(user["password"], credentials["password"]):
        return jsonify({"message": "Invalid email or password"}), 401

    token = create_access_token(identity=user["email"])
    return jsonify({"access_token": token}), 200

@app.route('/template', methods=['POST'])
@jwt_required()
def create_template():
    user_email = get_jwt_identity()

    try:
        template_data = template_schema.load(request.get_json())
    except ValidationError as error:
        return jsonify(error.messages), 400

    template_data["owner"] = user_email
    mongo.db.templates.insert_one(template_data)
    return jsonify({"message": "Template added successfully"}), 201

@app.route('/template', methods=['GET'])
@jwt_required()
def get_templates():
    user_email = get_jwt_identity()
    user_templates = list(mongo.db.templates.find({"owner": user_email}, {"_id": 0}))
    return jsonify({"templates": user_templates}), 200

@app.route('/template/<template_id>', methods=['GET'])
@jwt_required()
def get_template(template_id):
    user_email = get_jwt_identity()
    template_id = ObjectId(template_id)
    template = mongo.db.templates.find_one({"_id": template_id, "owner": user_email}, {"_id": 0})

    if not template:
        return jsonify({"message": "Template not found"}), 404

    return jsonify(template), 200

@app.route('/template/<template_id>', methods=['PUT'])
@jwt_required()
def update_template(template_id):
    user_email = get_jwt_identity()

    try:
        updated_data = template_schema.load(request.get_json())
    except ValidationError as error:
        return jsonify(error.messages), 400
    
    template_id = ObjectId(template_id)

    result = mongo.db.templates.update_one({"_id": template_id, "owner": user_email}, {"$set": updated_data})

    if result.matched_count == 0:
        return jsonify({"message": "Template not found or access denied"}), 404

    return jsonify({"message": "Template updated successfully"}), 200

@app.route('/template/<template_id>', methods=['DELETE'])
@jwt_required()
def delete_template(template_id):
    user_email = get_jwt_identity()
    template_id = ObjectId(template_id)

    result = mongo.db.templates.delete_one({"_id": template_id, "owner": user_email})

    if result.deleted_count == 0:
        return jsonify({"message": "Template not found or access denied"}), 404

    return jsonify({"message": "Template deleted successfully"}), 200

if __name__ == "__main__":
    app.run(debug=True,port=8000,host="0.0.0.0")

import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)

'''
@TODO uncomment the following line to initialize the datbase
!! NOTE THIS WILL DROP ALL RECORDS AND START YOUR DB FROM SCRATCH
!! NOTE THIS MUST BE UNCOMMENTED ON FIRST RUN
'''
db_drop_and_create_all()

# ROUTES
@app.route('/drinks')
def getDrinks():
    drinks = Drink.query.all()
    drinks_data = [drink.short() for drink in drinks]
    return jsonify({"success": True, "drinks": drinks_data}), 200

@app.route('/drinks-detail')
@requires_auth('get:drinks-detail')
def getDrinkDetails(payload):
    drinks = Drink.query.all()
    drinks_data = [drink.long() for drink in drinks]

    return jsonify({"success": True, "drinks": drinks_data}), 200

@app.route('/drinks', methods=['POST'])
@requires_auth('post:drinks')
def addDrink(payload):
    data = request.get_json()
    drink = Drink(title=data['title'], recipe=json.dumps(data['recipe']))
    drink.insert()
    return jsonify({"success": True, "drinks": drink.long()}), 200

@app.route('/drinks/<id>', methods=['PATCH'])
@requires_auth('patch:drinks')
def patchDrink(payload, id):
    drink = Drink.query.filter(Drink.id == id).one_or_none()
    if not drink: 
        abort(404)
    data = request.get_json()
    if 'title' in data:
        drink.title = data['title']
    if 'recipe' in data: 
        drink.recipe = data['recipe']
    drink.update()

    return jsonify({"success": True, "drinks": drink.long()}), 200

@app.route('/drinks/<id>', methods=['DELETE'])
@requires_auth('delete:drinks')
def deleteDrinks(payload, id):
    drink = Drink.query.filter(Drink.id == id).one_or_none()
    if not drink: 
        abort(404)
    drink.delete()
    return jsonify({"success": True, "delete": id})

# Error Handling
'''
Example error handling for unprocessable entity
'''
@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False,
        "error": 422,
        "message": "unprocessable"
    }), 422

@app.errorhandler(404)
def unauthorized(error):
    return jsonify({
        "success": False,
        "error": 404,
        "message": "Resource not found"
    }), 404

@app.errorhandler(AuthError)
def unauthorized(error):
    return jsonify({
        "success": False,
        "error": error.status_code,
        "message": error.error["description"]
    }), error.status_code
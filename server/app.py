#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        try:
            user = request.get_json()

            username = user["username"]
            password = user["password"]
            image_url = user["image_url"]
            bio = user["bio"]

        
            new_user = User( username=username, image_url=image_url, bio=bio )
            new_user.password_hash = password

            db.session.add(new_user)
            db.session.commit()

            return new_user.to_dict(),201
        except:
            return {'error': '422 Unprocessable Entity'}, 422



class CheckSession(Resource):
    def get(self):
        user_id = session["user_id"]
        user = User.query.filter(User.id==user_id).first()
        
        if not user:
            return {},401
        
        return user.to_dict(),200

class Login(Resource):
    def post(self):
        req = request.get_json()

        username = req["username"]
        password = req["password"]

        user = User.query.filter(User.username==username).first()

        if user:
            if user.authenticate(password):
                session["user_id"] = user.id
                return user.to_dict(), 200
        
        return {"error": "401 Unauthorized Access"}, 401

class Logout(Resource):
    def delete(self):
        session["user_id"] = None
        return {}, 401

class RecipeIndex(Resource):
    def get(self):
        user = User.query.filter(User.id == session['user_id']).first()
        if not user:
            return {}, 401
        return [recipe.to_dict() for recipe in user.recipes], 200
        
    def post(self):
        request_json = request.get_json()

        title = request_json['title']
        instructions = request_json['instructions']
        minutes_to_complete = request_json['minutes_to_complete']

        try:
            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=session['user_id'],
            )

            db.session.add(recipe)
            db.session.commit()

            return recipe.to_dict(), 201

        except:
            return {'error': '422 Unprocessable Entity'}, 422

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
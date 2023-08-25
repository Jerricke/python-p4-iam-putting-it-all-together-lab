#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe


class Signup(Resource):
    def post(self):
        username = request.get_json()["username"]
        password = request.get_json()["password"]
        password_confirmation = request.get_json()["password_confirmation"]
        image_url = request.get_json()["image_url"]
        bio = request.get_json()["bio"]

        if username and (password == password_confirmation) and image_url and bio:
            newUser = User(username=username, image_url=image_url, bio=bio)
            newUser.password_hash = password
            db.session.add(newUser)
            db.session.commit()
            session["user_id"] = newUser.id
            return newUser.to_dict(rules=("-_password_hash",)), 201
        else:
            return {"error": "422 Unprocessable Entity"}, 422


class CheckSession(Resource):
    def get(self):
        if session.get("user_id"):
            user = User.query.filter_by(id=session.get("user_id")).first()

            return user.to_dict(rules=("-_password_hash",)), 200
        return {}, 401


class Login(Resource):
    def post(self):
        username = request.get_json()["username"]
        password = request.get_json()["password"]

        user = User.query.filter_by(username=username).first()
        if user.authenticate(password):
            session["user_id"] = user.id
            return user.to_dict(), 200
        return {"error": "401 Unautorized"}, 401


class Logout(Resource):
    def delete(post):
        if session.get("user_id"):
            session["user_id"] = None
            return {}, 204
        return {"Error": "Unauthorize"}

    pass


class RecipeIndex(Resource):
    def get(self):
        if session.get("user_id"):
            recipes = [r.to_dict() for r in Recipe.query.all()]
            return recipes, 200
        return {"Error": "Unauthorized"}, 401

    def post(self):
        if session.get("user_id"):
            data = request.get_json()
            title = data["title"]
            instructions = data["instructions"]
            minutes_to_complete = data["minutes_to_complete"]
            user_id = session.get("user_id")
            if title and instructions and minutes_to_complete and user_id:
                newRecipe = Recipe(
                    title=title,
                    instructions=instructions,
                    minutes_to_complete=minutes_to_complete,
                    user_id=user_id,
                )
                db.session.add(newRecipe)
                db.session.commit()

                return newRecipe.to_dict(), 201
            return {"Error": "422 Unprocessable Entity"}, 422
        return {"Error": "401 Unauthorized"}, 401


api.add_resource(Signup, "/signup", endpoint="signup")
api.add_resource(CheckSession, "/check_session", endpoint="check_session")
api.add_resource(Login, "/login", endpoint="login")
api.add_resource(Logout, "/logout", endpoint="logout")
api.add_resource(RecipeIndex, "/recipes", endpoint="recipes")


if __name__ == "__main__":
    app.run(port=5555, debug=True)

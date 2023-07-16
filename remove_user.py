from app import app, db, User
with app.app_context():
    user_id = 1 # Replace with the ID of the user you want to remove
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        print("User account deleted successfully.")
    else:
        print("User account not found.")

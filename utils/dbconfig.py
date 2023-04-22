from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Create SQLAlchemy instance
db = SQLAlchemy()


def create_app(database_uri=None):
    """
    Create a Flask app and initialize SQLAlchemy with the provided database_uri.
    If database_uri is None, use a default local MySQL database.

    :param database_uri: URI for the database to connect to.
    :return: A Flask app instance with initialized SQLAlchemy.
    """

    # Create Flask app
    app = Flask(__name__)

    # Set the SQLAlchemy database URI and configuration options
    app.config['SQLALCHEMY_DATABASE_URI'] = database_uri or 'mysql+pymysql://admin:root123@localhost/pm'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_TABLE_PREFIX'] = 'pm_'

    # Initialize SQLAlchemy with the Flask app instance
    db.init_app(app)

    # Create all database tables
    with app.app_context():
        db.create_all()

    return app

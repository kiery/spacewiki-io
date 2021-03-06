import peewee
from playhouse.db_url import parse as parse_db_url
from playhouse.db_url import connect
import psycopg2
from flask import g, current_app, Blueprint
import dispatcher
import logging

BLUEPRINT = Blueprint('model', __name__)

@BLUEPRINT.before_app_request
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        g._database = db = connect(current_app.config['ADMIN_DB_URL'])
    ADMIN_DATABASE.initialize(db)

ADMIN_DATABASE = peewee.Proxy()

class BaseModel(peewee.Model):
    class Meta:
        database = ADMIN_DATABASE

class Space(BaseModel):
    slack_team_id = peewee.CharField()
    domain = peewee.CharField(default='')
    slack_access_token = peewee.CharField(default='')
    active = peewee.BooleanField(default=False)
    stripe_customer_id = peewee.CharField(default='')
    stripe_subscription_id = peewee.CharField(default='')

    @property
    def db_name(self):
        return "spacewiki_site_%s" % self.slack_team_id.lower()

    @property
    def db_url(self):
        return current_app.config['SPACE_DB_URL_PATTERN'] % self.db_name

    def make_space_database(self):
        parsed = parse_db_url(current_app.config['ADMIN_DB_URL'])
        db_string = 'dbname=%s'%(parsed['database'])
        if 'host' in parsed:
            db_string += ' host='+parsed['host']
        if 'user' in parsed:
            db_string += ' user='+parsed['user']
        if 'password' in parsed:
            db_string += ' password='+parsed['password']
        db = psycopg2.connect(db_string)
        db.autocommit = True
        cur = db.cursor()
        try:
            cur.execute("CREATE DATABASE %s" % self.db_name)
            logging.info("Created new database for team %s", self)
        except psycopg2.ProgrammingError:
            logging.debug("Team %s already has a database.", self)
            pass

    @staticmethod
    def from_team_slacker(slacker):
        slack_team = slacker.api.get('team.info').body
        team_id = slack_team['team']['id']
        domain = slack_team['team']['domain']
        try:
            space = Space.get(Space.slack_team_id == team_id)
            if space.domain != domain:
                space.domain = domain
                logging.info("Updating domain for %s", space)
            if space.slack_auth_token != slacker.api.token:
                space.slack_auth_token = slacker.api.token
                logging.info("Updating auth token for %s", space)
            space.save()
        except peewee.DoesNotExist:
            space = Space.create(slack_team_id = team_id,
                    domain=domain,
                    slack_auth_token=slacker.api.token)
            logging.info("Created new space for %s", space)
        return space

    @staticmethod
    def from_user_slacker(slacker):
        user_id = slacker.api.get('users.identity').body
        team_id = user_id['team']['id']
        try:
            space = Space.get(Space.slack_team_id == team_id)
            logging.debug("Space found for %s", team_id)
            return space
        except peewee.DoesNotExist:
            logging.debug("No space found for %s", team_id)
            return None

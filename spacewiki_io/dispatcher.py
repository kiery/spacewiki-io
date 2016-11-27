import logging
from threading import Lock
from spacewiki_io import model, routes
from flask import current_app, session, request, render_template
from flask.globals import _request_ctx_stack
from flask_login import current_user, login_user
import peewee
import spacewiki.app
import spacewiki.model
import spacewiki.auth

def confirm_logged_in():
    common_user = session.get('_spacewikiio_auth_id', None)
    if common_user is not None:
        del session['_spacewikiio_auth_id']
        try:
            u = spacewiki.model.Identity.get(spacewiki.model.Identity.auth_id ==
                    common_user, spacewiki.model.Identity.auth_type == 'slack')
            login_user(u)
        except peewee.DoesNotExist:
            pass
    if not current_user.is_authenticated:
        if not request.path.startswith('/static'):
            return spacewiki.auth.LOGIN_MANAGER.unauthorized()

def failed_auth():
    _request_ctx_stack.top.url_adapter.server_name = 'spacewiki.io'
    return routes.private()

def handle_deadspace():
    if not request.path.startswith('/static'):
        return routes.deadspace()

def make_wiki_app(subdomain):
    import app
    hostedApp = app.create_app()
    with hostedApp.app_context():
        model.get_db()
        try:
            space = model.Space.get(domain=subdomain)
        except peewee.DoesNotExist:
            logging.info("Spacewiki is not yet configured for %s.", subdomain)
            hostedApp.before_request(handle_deadspace)
            return hostedApp
        db_url = space.db_url
    app = spacewiki.app.create_app()
    app.before_request(confirm_logged_in)
    app.secret_key = hostedApp.secret_key
    app.config['SLACK_KEY']  = hostedApp.config['SLACK_KEY']
    app.config['DATABASE_URL'] = db_url
    app.config['SITE_NAME'] = subdomain
    app.config['UPLOAD_PATH'] = '/srv/spacewiki/uploads/%s'%(subdomain)
    app.config['ASSETS_CACHE'] = '/tmp/'
    app.config['LOGIN_NEEDED'] = True
    app.config['DEADSPACE'] = False
    app.register_blueprint(routes.BLUEPRINT)
    app.logger.setLevel(logging.DEBUG)
    spacewiki.auth.LOGIN_MANAGER.unauthorized_handler(failed_auth)
    with app.app_context():
        spacewiki.model.syncdb()
    return app


class SubdomainDispatcher(object):
    def __init__(self, domain, create_app, create_default_app):
        self.domain = domain
        self.create_app = create_app
        self.create_default_app = create_default_app
        self.lock = Lock()
        self.instances = {}

    def get_application(self, host):
        logging.info("Got request for %s while serving %s", host, self.domain)
        host = host.split(':')[0]

        if not host.endswith(self.domain):
            return self.create_default_app()

        subdomain = host[:-len(self.domain)].rstrip('.')

        if subdomain == '':
            return self.create_default_app()

        with self.lock:
            app = self.instances.get(subdomain)
            if app is None:
                logging.info("Booting new application for %s", host)
                app = self.create_app(subdomain)
                self.instances[subdomain] = app
            return app

    def __call__(self, environ, start_response):
        app = self.get_application(environ['HTTP_HOST'])
        return app(environ, start_response)

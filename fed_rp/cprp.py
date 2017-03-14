import base64
import hashlib

import cherrypy
import requests

def handle_error():
    cherrypy.response.status = 500
    cherrypy.response.body = [
        "<html><body>Sorry, an error occured</body></html>"
    ]


def get_symkey(link):
    md5 = hashlib.md5()
    md5.update(link.encode("utf-8"))
    return base64.b16encode(md5.digest()).decode("utf-8")


class Root(object):
    @cherrypy.expose
    def index(self):
        response = [
            '<html><head>',
            '<title>My OpenID Connect RP</title>',
            '<link rel="stylesheet" type="text/css" href="/static/theme.css">'
            '</head><body>'
            "<h1>Welcome to my OpenID Connect RP</h1>",
            '</body></html>'
        ]
        return '\n'.join(response)


class Consumer(Root):
    _cp_config = {'request.error_response': handle_error}

    def __init__(self, rp, scope, response_type, path):
        self.rp = rp
        self.scope = scope
        self.response_type = response_type
        self.path = path

    def __index__(self, uid='', iss=''):
        link = ''
        if iss:
            link = iss
        elif uid:
            try:
                link = self.rp.find_srv_discovery_url(resource=uid)
            except requests.ConnectionError:
                return cherrypy.HTTPError(
                    message="Webfinger lookup failed, connection error")

            self.rp.srv_discovery_url = link
            #cherrypy.session['callback'] = True

            sid, location = self.rp.begin(scope=self.scope,
                                          response_type=self.response_type,
                                          path=self.path)



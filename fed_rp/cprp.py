import re
import base64
import hashlib
import os

import cherrypy
import logging
import requests
from html import entities as htmlentitydefs

from jwkest import as_bytes

logger = logging.getLogger(__name__)


def handle_error():
    cherrypy.response.status = 500
    cherrypy.response.body = [
        "<html><body>Sorry, an error occured</body></html>"
    ]


def get_symkey(link):
    md5 = hashlib.md5()
    md5.update(link.encode("utf-8"))
    return base64.b16encode(md5.digest()).decode("utf-8")


# this pattern matches substrings of reserved and non-ASCII characters
pattern = re.compile(r"[&<>\"\x80-\xff]+")

# create character map
entity_map = {}

for i in range(256):
    entity_map[chr(i)] = "&#%d;" % i

for entity, char in htmlentitydefs.entitydefs.items():
    if char in entity_map:
        entity_map[char] = "&%s;" % entity


def escape_entity(m, get=entity_map.get):
    return "".join(map(get, m.group()))


def escape(string):
    return pattern.sub(escape_entity, string)


def create_result_page(userinfo, access_token):
    """
    Display information from the Authentication.
    """
    element = ""
    if result[0]:
        element += "<p>You have successfully loged in!</p>"
        element += "<div class='row'>"
        element += "<div class='col-md-10'>Accesstoken</div>"
        element += "</div>"
        element += "<div class='row'>"
        element += "<div class='col-md-10'>" + str(result[2]) + "</div>"
        element += "</div>"
        try:
            text = str(result[3].authorization_endpoint)
            element += "<div class='row'>"
            element += "<div class='col-md-3'>Authorization endpoint</div>"
            element += "<div class='col-md-7'>" + text + "</div>"
            element += "</div>"
        except:
            pass
        try:
            text = str(result[3].registration_endpoint)
            element += "<div class='row'>"
            element += "<div class='col-md-3'>Registration endpoint</div>"
            element += "<div class='col-md-7'>" + text + "</div>"
            element += "</div>"
        except:
            pass
        try:
            text = str(result[3].token_endpoint)
            element += "<div class='row'>"
            element += "<div class='col-md-3'>Token endpoint</div>"
            element += "<div class='col-md-7'>" + text + "</div>"
            element += "</div>"
        except:
            pass
        try:
            text = str(result[3].userinfo_endpoint)
            element += "<div class='row'>"
            element += "<div class='col-md-3'>User info endpoint</div>"
            element += "<div class='col-md-7'>" + text + "</div>"
            element += "</div>"
        except:
            pass
        for key, value in result[1].items():
            element += "<div class='row'>"
            element += "<div class='col-md-3'>" + escape(str(key)) + "</div>"
            element += "<div class='col-md-7'>" + escape(str(value)) + "</div>"
            element += "</div>"
    else:
        element += "<p>You have failed to connect to the designated OP with " \
                   "the message:</p><p> " + \
                   result[1] + "</p>"
    return element


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

    def __init__(self, rph, html_home='.', static_dir='static'):
        self.rph = rph
        self.html_home = html_home
        self.static_dir = static_dir

    @cherrypy.expose
    def index(self, uid='', iss=''):
        link = ''
        if iss:
            link = iss
        elif uid:
            try:
                link = self.rph.find_srv_discovery_url(
                    resource="acct:{}".format(uid))
            except requests.ConnectionError:
                raise cherrypy.HTTPError(
                    message="Webfinger lookup failed, connection error")
        else:
            fname = os.path.join(self.html_home, 'opbyuid.html')
            return as_bytes(open(fname, 'r').read())

        if link:
            resp_headers = self.rph.begin(link)
            raise cherrypy.HTTPRedirect(resp_headers['Location'])

    @cherrypy.expose
    def authz_cb(self, op_hash='', **kwargs):
        try:
            rp = self.rph.issuer2rp[self.rph.hash2issuer[op_hash]]
        except KeyError:
            raise cherrypy.HTTPError(400,
                                     "Response to something I hadn't asked for")

        res = self.rph.phaseN(rp, kwargs)

        if res[0] is True:
            return as_bytes(create_result_page(*res[1:]))
        else:
            raise cherrypy.HTTPError(400, res[1])

    def _cp_dispatch(self, vpath):
        # Only get here if vpath != None
        ent = cherrypy.request.remote.ip
        logger.info('ent:{}, vpath: {}'.format(ent, vpath))

        if vpath[0] in self.static_dir:
            return self
        elif len(vpath) == 2:
            a = vpath.pop(0)
            b = vpath.pop(0)
            if a == 'rp':
                cherrypy.request.params['uid'] = b
                return self
            elif a == 'authz_cb':
                cherrypy.request.params['op_hash'] = b
                return self.authz_cb

        return self

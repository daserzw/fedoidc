# -*- coding:utf-8 -*-
from mako import cache
from mako import filters
from mako import runtime

UNDEFINED = runtime.UNDEFINED
STOP_RENDERING = runtime.STOP_RENDERING
__M_dict_builtin = dict
__M_locals_builtin = locals
_magic_number = 10
_modified_time = 1487077272.541233
_enable_loop = True
_template_filename = 'htdocs/login.mako'
_template_uri = 'login.mako'
_source_encoding = 'utf-8'
_exports = []


def render_body(context,**pageargs):
    __M_caller = context.caller_stack._push_frame()
    try:
        __M_locals = __M_dict_builtin(pageargs=pageargs)
        passwd_title = context.get('passwd_title', UNDEFINED)
        password = context.get('password', UNDEFINED)
        policy_uri = context.get('policy_uri', UNDEFINED)
        acr = context.get('acr', UNDEFINED)
        query = context.get('query', UNDEFINED)
        action = context.get('action', UNDEFINED)
        logo_uri = context.get('logo_uri', UNDEFINED)
        login = context.get('login', UNDEFINED)
        tos_uri = context.get('tos_uri', UNDEFINED)
        title = context.get('title', UNDEFINED)
        login_title = context.get('login_title', UNDEFINED)
        __M_writer = context.writer()
        __M_writer('<html>\n  <head>\n    <title>')
        __M_writer(str(title))
        __M_writer('</title>\n  </head>\n    <body>\n        <div class="login_form" class="block">\n            <form action="')
        __M_writer(str(action))
        __M_writer('" method="post" class="login form">\n                <input type="hidden" name="query" value="')
        __M_writer(str(query))
        __M_writer('"/>\n                <input type="hidden" name="acr_values" value="')
        __M_writer(str(acr))
        __M_writer('"/>\n                <table>\n                    <tr>\n                        <td>')
        __M_writer(str(login_title))
        __M_writer('</td>\n                        <td><input type="text" name="login"\n                                   value="')
        __M_writer(str(login))
        __M_writer('"/></td>\n                    </tr>\n                    <tr>\n                        <td>')
        __M_writer(str(passwd_title))
        __M_writer('</td>\n                        <td><input type="password" name="password"\n                        value="')
        __M_writer(str(password))
        __M_writer('"/></td>\n                    </tr>\n                    <tr>\n                        <td></td>\n                        <td><input type="submit" name="form.commit"\n                                value="Log In"/></td>\n                    </tr>\n                </table>\n            </form>\n')
        if logo_uri:
            __M_writer('                <img src="')
            __M_writer(str(logo_uri))
            __M_writer('" alt="Client logo">\n')
        if policy_uri:
            __M_writer('              <a href="')
            __M_writer(str(policy_uri))
            __M_writer('"><strong>Client&#39;s Policy</strong></a>\n')
        if tos_uri:
            __M_writer('                <a href="')
            __M_writer(str(tos_uri))
            __M_writer('"><strong>Client&#39;s Terms of Service</strong></a>\n')
        __M_writer('        </div>\n    </body>\n</html>\n')
        return ''
    finally:
        context.caller_stack._pop_frame()


"""
__M_BEGIN_METADATA
{"filename": "htdocs/login.mako", "line_map": {"67": 61, "16": 0, "32": 1, "33": 3, "34": 3, "35": 7, "36": 7, "37": 8, "38": 8, "39": 9, "40": 9, "41": 12, "42": 12, "43": 14, "44": 14, "45": 17, "46": 17, "47": 19, "48": 19, "49": 28, "50": 29, "51": 29, "52": 29, "53": 31, "54": 32, "55": 32, "56": 32, "57": 34, "58": 35, "59": 35, "60": 35, "61": 37}, "uri": "login.mako", "source_encoding": "utf-8"}
__M_END_METADATA
"""

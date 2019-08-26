# -*- coding: utf-8 -*-

from odoo import http
from odoo.http import request
from odoo.addons.web.controllers.main import login_and_redirect

import werkzeug.utils
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings

# from odoo.modules.registry import RegistryManager
import logging

logger = logging.getLogger(__name__)

import http.client as http_client
http_client.HTTPConnection.debuglevel = 1


class AuthSamlShibboleth(http.Controller):
    def init_saml_auth(self, req):
        custom_path = request.env['ir.config_parameter'].sudo().get_param("auth_saml.path")
        auth = OneLogin_Saml2_Auth(req, custom_base_path=custom_path)
        return auth

    def prepare_request(self, data, web_base):
        # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
        result = {
            'https': 'on',
            'http_host': web_base,
            'script_name': "/shibboleth/?acs",
            'server_port': "443",
            'get_data': data or '',
            'post_data': data or '',
        }
        return result

    @http.route(['/shibboleth/metadata'], type='http', auth="public")
    def metadata(self, **kw):
        """ returns metadata """
        custom_path = request.env['ir.config_parameter'].sudo().sudo().get_param("auth_saml.path")
        saml_settings = OneLogin_Saml2_Settings(settings=None, custom_base_path=custom_path, sp_validation_only=False)
        metadata = saml_settings.get_sp_metadata()
        errors = saml_settings.validate_metadata(metadata)

        if len(errors) == 0:
            resp = request.make_response(metadata, headers=[('Content-Type', 'text/xml')])
        else:
            resp = request.make_response(errors, headers=[('Content-Type', 'text/xml')])
        return resp

    @http.route(['/shibboleth'], type='http', auth="public", csrf=False)
    def main_controller(self, **kw):
        data = kw
        web_base = request.env['ir.config_parameter'].sudo().get_param("web.base.url").replace("https://", '')
        req = self.prepare_request(data, web_base)
        try:
            auth = self.init_saml_auth(req)
        except Exception as e:
            url = "/web/login?error=" + str(e)
            logger.warning(
                'Exception : %s',
                str(e)
            )
            return werkzeug.utils.redirect(url)

        if 'acs' in data.keys():
            auth.process_response()
            errors = auth.get_errors()
            logger.warning(
                'Errors : %s',
                errors
            )
            logger.warning("%s", auth.get_last_error_reason())
            if not errors:
                if auth.is_authenticated():
                    attrs = auth.get_attributes()
                    name_id = auth.get_nameid()
                    logger.warning("Nameid: %s", name_id)
                    # logger.warning("Object: %s", auth.__dict__)
                    logger.warning("Object: %s", dir(auth))
                    logger.warning(
                        'Attrs : %s',
                        attrs
                    )
                    logger.warning(
                        'Auth : %s',
                        auth
                    )
                    login = name_id.lower()
                    # fgs = attrs.get('urn:oid:2.16.840.1.113730.3.1.3')[0]
                    # fgs = '%08d' % int(fgs)
                    user = request.env['res.users'].sudo().search([('login', 'ilike', login)])
                    if user:
                        user.write({'saml_nameid': name_id})
                    else:
                        # # user = self._create_user(fgs, login, name_id)
                        # if not user:
                        url = "/web/login?error=Your account doesn\'t exist in our database, please contact the administrator"
                        return werkzeug.utils.redirect(url)
                    request.env.cr.commit()
                    return login_and_redirect(request.env.cr.dbname, login, name_id, redirect_url=data.get('RelayState') or '/')
                else:
                    url = "/web/login?error=You are not authenticated"
            else:

                url = "/web/login?error=" + str(errors)
            return werkzeug.utils.redirect(url)
        else:
            self.prepare_request(data, web_base)
            return_to = data.get('return_to') or '/'
            url = auth.login(return_to=return_to)
            return werkzeug.utils.redirect(url)

    def _create_user(self, fgs, login, name_id):
        if not fgs or not login or not name_id:
            return False
        partner = request.env['res.partner'].sudo().search([
            ('fgs', '=', fgs),
            ('contact_type', '!=', 'attached'),
            ('is_company', '=', False)
        ])
        PortalUsersEnv = request.env['res.users'].with_context({'no_reset_password': True})
        group_portal_id = request.env.ref('base.group_portal')
        if len(partner) == 1:
            lang_id = request.env['res.lang'].search([('code', '=', 'fr_FR')]) or request.env['res.lang'].search([], limit=1)
            return PortalUsersEnv.sudo().create({
                'login': login,
                'partner_id': partner.id,
                'saml_nameid': name_id,
                'groups_id': [(6, 0, [group_portal_id.id])],
                'lang': lang_id.code,
                'tz':  'Europe/Brussels',
            })
        return False
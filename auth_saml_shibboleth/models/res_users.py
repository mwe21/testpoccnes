import odoo
from odoo import models, api, fields


class ResUsers(models.Model):
    _inherit = 'res.users'

    saml_nameid = fields.Char('SAML name id', readonly=True, groups='ucl_contact.group_crm_admin')

    @api.model
    def _check_credentials(self, password):
        try:
            return super(ResUsers, self)._check_credentials(password)
        except odoo.exceptions.AccessDenied:
            if password:
                res = self.env['res.users'].sudo().search([
                    ('id', '=', self.env.user.id),
                    ('saml_nameid', '=', password)
                ])
            if not res:
                raise

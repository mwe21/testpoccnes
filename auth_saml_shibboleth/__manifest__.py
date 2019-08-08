{
    'name': 'Authentication SAML Shibboleth',
    'version': '0.3',
    'category': 'Authentication',
    'summary': 'Authentication SAML Shibboleth',
    'description': """
Installation:
-------------

Somewhere on your computer you have a folder with this arborescence. It has to be specified in your system parameters (auth_saml.path):

    SAML

    |-advanced_settings.json

    |-setting.json

    |-certs

       |- idp.crt

       |- sp.crt

       |- sp.key

for more information about setting up the module, you can go to : https://github.com/onelogin/python-saml

""",
    'author': 'Odoo SA',
    'depends': [
        'base',
        'website',
    ],
    'data': [
        'views/res_users.xml',
        'data/data.xml'

    ],
}

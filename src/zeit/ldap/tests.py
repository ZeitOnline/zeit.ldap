import os
import unittest
import zeit.cms.testing
import zeit.ldap.authentication
import zeit.ldap.connection
import zope.component


ZCML_LAYER = zeit.cms.testing.ZCMLLayer(bases=(zeit.cms.testing.CONFIG_LAYER,))
ZOPE_LAYER = zeit.cms.testing.ZopeLayer(bases=(ZCML_LAYER,))


class CacheLayer(zeit.cms.testing.CacheLayer):

    defaultBases = (zeit.cms.testing.CONFIG_LAYER,)

    def setUp(self):
        zeit.cms.application.configure_dogpile_cache(None)


DOGPILE_CACHE_LAYER = CacheLayer()


class FakeLdap:

    def connect(self, dn=None, password=None):
        # Accept everything
        return self

    def search(self, base, scope, filter, **kw):
        dn = 'mydn'
        entry = {'login': ['foo'], 'mail': ['test@example.com']}
        return [(dn, entry)]


class AuthenticationTest(unittest.TestCase):

    layer = DOGPILE_CACHE_LAYER

    def setUp(self):
        super().setUp()
        gsm = zope.component.getGlobalSiteManager()
        self.fake_ldap = FakeLdap()
        self.auth = zeit.ldap.authentication.ldapPluginFactory()
        gsm.registerUtility(
            self.fake_ldap, zeit.ldap.connection.ILDAPAdapter,
            name=self.auth.adapterName)
        self.auth.idAttribute = 'dn'
        self.auth.loginAttribute = 'login'

    def tearDown(self):
        gsm = zope.component.getGlobalSiteManager()
        gsm.unregisterUtility(
            self.fake_ldap, zeit.ldap.connection.ILDAPAdapter,
            name=self.auth.adapterName)
        super().tearDown()

    def test_empty_passwords_are_rejected(self):
        self.assertFalse(self.auth.authenticateCredentials(
            dict(login='foo', password='')))

    def test_non_empty_passwords_pass(self):
        self.assertTrue(self.auth.authenticateCredentials(
            dict(login='foo', password='bar')))

    def test_returns_email_address_in_description(self):
        info = self.auth.authenticateCredentials(
            dict(login='foo', password='bar'))
        self.assertEqual('test@example.com', info.description)


class LDAPIntegrationTest(unittest.TestCase):

    layer = DOGPILE_CACHE_LAYER

    def setUp(self):
        super().setUp()
        gsm = zope.component.getGlobalSiteManager()
        env = os.environ
        self.ldap = zeit.ldap.connection.LDAPAdapter(
            host=env['ZEIT_LDAP_HOST'],
            bindDN=env['ZEIT_LDAP_BIND_USERNAME'],
            bindPassword=env['ZEIT_LDAP_BIND_PASSWORD'])
        gsm.registerUtility(self.ldap)

    def tearDown(self):
        gsm = zope.component.getGlobalSiteManager()
        gsm.unregisterUtility(
            self.ldap, zeit.ldap.connection.ILDAPAdapter)
        super().tearDown()

    def test_authenticate_works(self):
        env = os.environ
        auth = zeit.ldap.authentication.LDAPAuthentication()
        auth.searchScope = 'sub'
        auth.filterQuery = env['ZEIT_LDAP_FILTER_QUERY']
        auth.idAttribute = env['ZEIT_LDAP_LOGIN_FIELD']
        auth.loginAttribute = env['ZEIT_LDAP_LOGIN_FIELD']
        principal = auth.authenticateCredentials(
            {'login': env['ZEIT_LDAP_USERNAME'],
             'password': env['ZEIT_LDAP_PASSWORD']})
        self.assertEqual(principal.login, env['ZEIT_LDAP_USERNAME'])


def test_suite():
    return zeit.cms.testing.FunctionalDocFileSuite(
        'README.txt',
        layer=ZOPE_LAYER)

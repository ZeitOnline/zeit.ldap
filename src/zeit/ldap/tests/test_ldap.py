import os
import unittest
import zeit.ldap.authentication
import zeit.ldap.connection
import zeit.ldap.testing
import zope.component


class FakeLdap:

    def connect(self, dn=None, password=None):
        # Accept everything
        return self

    def search(self, base, scope, filter, **kw):
        dn = 'mydn'
        entry = {'login': ['foo'], 'mail': ['test@example.com']}
        return [(dn, entry)]


class AuthenticationTest(unittest.TestCase):

    layer = zeit.ldap.testing.DOGPILE_CACHE_LAYER

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
        self.auth.titleAttribute = 'login'
        self.auth.descriptionAttribute = 'mail'

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

    layer = zeit.ldap.testing.DOGPILE_CACHE_LAYER

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
        auth.titleAttribute = env['ZEIT_LDAP_LOGIN_FIELD']
        auth.descriptionAttribute = env['ZEIT_LDAP_LOGIN_FIELD']
        principal = auth.authenticateCredentials(
            {'login': env['ZEIT_LDAP_USERNAME'],
             'password': env['ZEIT_LDAP_PASSWORD']})
        self.assertEqual(principal.login, env['ZEIT_LDAP_USERNAME'])
import pyramid_dogpile_cache2
import unittest
import zeit.cms.testing
import zeit.ldap.authentication
import zeit.ldap.connection
import zope.component


ZCML_LAYER = zeit.cms.testing.ZCMLLayer(bases=(zeit.cms.testing.CONFIG_LAYER,))
ZOPE_LAYER = zeit.cms.testing.ZopeLayer(bases=(ZCML_LAYER,))


class FakeLdap(object):

    def connect(self, dn=None, password=None):
        # Accept everything
        return self

    def search(self, base, scope, filter, **kw):
        dn = 'mydn'
        entry = {'login': ['foo'], 'mail': ['test@example.com']}
        return [(dn, entry)]


class AuthenticationTest(unittest.TestCase):

    def setUp(self):
        super(AuthenticationTest, self).setUp()
        gsm = zope.component.getGlobalSiteManager()
        self.fake_ldap = FakeLdap()
        self.auth = zeit.ldap.authentication.ldapPluginFactory()
        gsm.registerUtility(
            self.fake_ldap, zeit.ldap.connection.ILDAPAdapter,
            name=self.auth.adapterName)
        self.auth.idAttribute = 'dn'
        self.auth.loginAttribute = 'login'
        pyramid_dogpile_cache2.configure_dogpile_cache({
            'dogpile_cache.backend': 'dogpile.cache.memory',
            'dogpile_cache.regions': 'config, feature',
            'dogpile_cache.config.expiration_time': 0,
            'dogpile_cache.feature.expiration_time': 15,
        })

    def tearDown(self):
        gsm = zope.component.getGlobalSiteManager()
        gsm.unregisterUtility(
            self.fake_ldap, zeit.ldap.connection.ILDAPAdapter,
            name=self.auth.adapterName)
        super(AuthenticationTest, self).tearDown()

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


def test_suite():
    return zeit.cms.testing.FunctionalDocFileSuite(
        'README.txt',
        layer=ZOPE_LAYER)

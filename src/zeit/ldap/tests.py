# Copyright (c) 2007-2012 gocept gmbh & co. kg
# See also LICENSE.txt

import os
import unittest
import zope.component
import ldapadapter.interfaces
import zeit.cms.testing
import zeit.ldap.authentication
from zope.testing import doctest


LDAPLayer = zeit.cms.testing.ZCMLLayer(
    os.path.join(os.path.dirname(__file__), 'ftesting.zcml'),
    __name__, 'LDAPLayer', allow_teardown=True)


class FakeLdap(object):

    def connect(self, dn=None, password=None):
        # Accept everything
        return self

    def search(self, base, scope, filter):
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
            self.fake_ldap, ldapadapter.interfaces.ILDAPAdapter,
            name=self.auth.adapterName)
        self.auth.idAttribute = 'dn'
        self.auth.loginAttribute = 'login'

    def tearDown(self):
        gsm = zope.component.getGlobalSiteManager()
        gsm.unregisterUtility(
            self.fake_ldap, ldapadapter.interfaces.ILDAPAdapter,
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
    suite = unittest.TestSuite()
    suite.addTest(zeit.cms.testing.FunctionalDocFileSuite(
        'README.txt',
        optionflags=doctest.INTERPRET_FOOTNOTES|doctest.ELLIPSIS,
        layer=LDAPLayer))
    suite.addTest(unittest.makeSuite(AuthenticationTest))
    return suite

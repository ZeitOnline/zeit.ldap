import zeit.cms.testing
import zeit.ldap.testing


def test_suite():
    return zeit.cms.testing.FunctionalDocFileSuite(
        'README.txt',
        layer=zeit.ldap.testing.ZOPE_LAYER,
        package='zeit.ldap')

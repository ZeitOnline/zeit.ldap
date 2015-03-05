import zeit.cms.testing
import zope.authentication.interfaces
import zope.generations.utility


def evolve(context):
    root = zope.generations.utility.getRootFolder(context)
    with zeit.cms.testing.site(root):
        pau = zope.component.getUtility(
            zope.authentication.interfaces.IAuthentication)
        pau.authenticatorPlugins = ('ldap', 'principalregistry')
        pau.credentialsPlugins = (
            'No Challenge if Authenticated',
            'Session Credentials')

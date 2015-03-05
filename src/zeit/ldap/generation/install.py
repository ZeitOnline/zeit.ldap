import zeit.cms.generation.install
import zeit.cms.testing
import zope.authentication.interfaces
import zope.pluggableauth.authentication


def install(root):
    site_manager = zope.component.getSiteManager()

    auth = zeit.cms.generation.install.installLocalUtility(
        site_manager,
        zope.pluggableauth.authentication.PluggableAuthentication,
        'authentication',
        zope.authentication.interfaces.IAuthentication)
    auth.authenticatorPlugins = ('ldap', 'principalregistry')
    auth.credentialsPlugins = (
        'No Challenge if Authenticated',
        'Session Credentials')


def evolve(context):
    root = zope.generations.utility.getRootFolder(context)
    with zeit.cms.testing.site(root):
        install(root)

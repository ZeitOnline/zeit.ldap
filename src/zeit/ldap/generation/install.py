import zeit.cms.generation
import zeit.cms.generation.install
import zope.authentication.interfaces
import zope.pluggableauth.authentication


def install(root):
    site_manager = zope.component.getSiteManager()

    auth = zeit.cms.generation.install.installLocalUtility(
        site_manager,
        zope.pluggableauth.authentication.PluggableAuthentication,
        'authentication',
        zope.authentication.interfaces.IAuthentication)

    auth['principalfolder'] = \
        zope.pluggableauth.plugins.principalfolder.PrincipalFolder()

    auth.authenticatorPlugins = (
        'ldap',
        'principalfolder',
        # Since zope.principalregistry raise PrincipalLookupError instead of
        # returning None (thus continuing to the next plugin), it must come
        # last in the list.
        'principalregistry',
    )
    # Note: XML-RPC requires Basic Auth, which works because the xmlrpc-views
    # are called via URL "/", so a first authentication attempt happens
    # *before* traversal, using the IAuthentication utility from
    # zope.principalregistry (which uses Basic Auth), which is non-persistent,
    # and thus registered at zope.component.getGlobalSiteManager(). The PAU is
    # used only *after* traversal (and then uses form-based authentication).
    auth.credentialsPlugins = (
        'No Challenge if Authenticated',
        'Session Credentials',
    )


def evolve(context):
    zeit.cms.generation.do_evolve(context, install)

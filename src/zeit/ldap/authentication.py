from zeit.cms.interfaces import CONFIG_CACHE
from zope.pluggableauth.factories import PrincipalInfo
from zope.publisher.interfaces.http import IHTTPRequest
import zeit.ldap.azure
import zope.app.appsetup.product
import zope.authentication.interfaces
import zope.component
import zope.component.hooks
import zope.pluggableauth.authentication
import zope.pluggableauth.interfaces
import zope.pluggableauth.plugins.httpplugins
import zope.pluggableauth.plugins.session
import zope.principalregistry.principalregistry
import zope.schema


@zope.interface.implementer(zope.pluggableauth.interfaces.IAuthenticatorPlugin)
class PrincipalRegistryAuthenticator:
    """Connects PAU to zope.principalregistry."""

    registry = zope.principalregistry.principalregistry.principalRegistry

    def authenticateCredentials(self, credentials):
        if credentials is None:
            return None

        try:
            user = self.registry.getPrincipalByLogin(credentials['login'])
        except KeyError:
            user = None
        if user is None:
            return None
        if not user.validate(credentials['password']):
            return None

        return self._principal_info(user)

    def principalInfo(self, id):
        try:
            user = self.registry.getPrincipal(id)
        except zope.authentication.interfaces.PrincipalLookupError:
            return None
        if user is None:
            return None
        return self._principal_info(user)

    def _principal_info(self, user):
        return PrincipalInfo(user.id, user.getLogin(), user.title, '')


@zope.interface.implementer(zope.pluggableauth.interfaces.ICredentialsPlugin)
class OIDCHeaderCredentials:

    email_header = 'X-OIDC-Email'
    name_header = 'X-OIDC-User'
    logout_url = '/oauth2/sign_in'  # clears oidc cookies and prompts to login

    def extractCredentials(self, request):
        if not IHTTPRequest.providedBy(request):
            return None
        if self.email_header not in request.headers:
            return None
        return {
            'oidc': True,  # Use a marker interface instead?
            'login': request.headers[self.email_header],
            'password': '',  # Implicit zope.pluggableauth protocol
            'name': request.headers.get(  # PEP-3333 is weird
                self.name_header, '').encode('latin-1').decode('utf-8'),
        }

    def challenge(self, request):
        # Challenging is already handled by nginx+oauth-proxy.
        return False

    def logout(self, request):
        home = zope.traversing.browser.absoluteURL(
            zope.component.hooks.getSite(), request)
        request.response.redirect(home + self.logout_url)
        return True


@zope.interface.implementer(zope.pluggableauth.interfaces.ICredentialsPlugin)
def oidc_from_product_config():
    config = zope.app.appsetup.product.getProductConfiguration(
        'zeit.ldap') or {}
    plugin = OIDCHeaderCredentials()
    settings = {
        'email_header': 'oidc-header-email',
        'name_header': 'oidc-header-name',
        'logout_url': 'oidc-logout-url',
    }
    for prop, key in settings.items():
        if key in config:
            setattr(plugin, prop, config[key])
    return plugin


class IAzureSearchSchema(zope.interface.Interface):

    query = zope.schema.TextLine(
        title='Azure AD Name (substring)',
        required=False)


@zope.interface.implementer(
    zope.pluggableauth.interfaces.IAuthenticatorPlugin,
    zope.pluggableauth.interfaces.IQueriableAuthenticator,
    zope.pluggableauth.interfaces.IQuerySchemaSearch)
class AzureADAuthenticator:

    def authenticateCredentials(self, credentials):
        if credentials is None:
            return None
        if 'oidc' not in credentials:  # See OIDCHeaderCredentials
            return None
        email = credentials['login'].lower()
        return PrincipalInfo(
            email, email, credentials['name'], email)

    @CONFIG_CACHE.cache_on_arguments()
    def principalInfo(self, id):
        # `id` is the email address
        id = id.lower()
        ad = zope.component.getUtility(zeit.ldap.azure.IActiveDirectory)
        user = ad.get_user(id)
        if not user:
            return None
        return PrincipalInfo(id, id, user['displayName'], id)

    schema = IAzureSearchSchema

    def search(self, query, start=None, batch_size=None):
        ad = zope.component.getUtility(zeit.ldap.azure.IActiveDirectory)
        result = [
            x['userPrincipalName'].lower()
            for x in ad.search_users(query['query'])]
        if start is None:
            start = 0
        if batch_size is None:
            batch_size = len(result)
        return result[start:start + batch_size]


class BasicAuthCredentials(
        zope.pluggableauth.plugins.httpplugins.HTTPBasicAuthCredentialsPlugin):
    """We only support basic auth on non-public ingress endpoints, e.g. for
    xmlrpc requests and administrative access.
    """

    header_name = 'X-Zope-Basicauth'

    def _enabled(self, request):
        return request.headers.get(self.header_name, '') != 'disabled'

    def extractCredentials(self, request):
        if not self._enabled(request):
            return None
        return super().extractCredentials(request)

    def challenge(self, request):
        if not self._enabled(request):
            return False
        return super().challenge(request)


class SessionCredentials(
        zope.pluggableauth.plugins.session.SessionCredentialsPlugin):
    """Make PAU work as a non-persistent utility.

    The upstream assumption is to be persistent, i.e. at least traversal to
    the root folder will have already happened, so any other persistent
    utilities (like the zope.session ClientIdManager) are available.
    We don't need/want the PAU to be persistent, so we register it with the
    global ZCA registry. This means, it can and will be used before any
    traversal happens (e.g. by ZCML to access principals for grant operations).
    Since actual authentication only makes sense after at least traversing to
    the root folder, we can simply ignore attempts that happen before that.
    """

    def extractCredentials(self, request):
        # The "proper" way to check would be `ISession(request)`, but since
        # this is going to be called on every request before traversal starts,
        # let's make it as cheap-to-fail as possible.
        if zope.component.queryUtility(
                zope.session.interfaces.IClientIdManager) is None:
            return None
        return super().extractCredentials(request)

    def logout(self, request):
        # Strictly speaking, things like redirecting the browser are the job of
        # the logout view. But since we need different treatments for session
        # and oidc, it's probably fair to put them in their credentials plugin.
        if not super().logout(request):
            return False
        home = zope.traversing.browser.absoluteURL(
            zope.component.hooks.getSite(), request)
        request.response.redirect(home)
        return True


@zope.interface.implementer(zope.authentication.interfaces.IAuthentication)
def pauFactory():
    conf = zope.app.appsetup.product.getProductConfiguration('zeit.ldap') or {}
    pau = zope.pluggableauth.authentication.PluggableAuthentication()
    pau.authenticatorPlugins = conf['authenticator-plugins'].split(',')
    pau.credentialsPlugins = conf['credentials-plugins'].split(',')
    # Make Rotterdam UI happy
    pau.__parent__ = FakeRoot()
    pau.__name__ = 'authentication'
    return pau


@zope.interface.implementer(zope.location.interfaces.IRoot)
class FakeRoot:
    pass

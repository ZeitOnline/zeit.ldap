from ast import literal_eval
from zeit.cms.interfaces import CONFIG_CACHE
from zeit.ldap.connection import ServerDown, InvalidCredentials, NoSuchObject
from zope.pluggableauth.factories import PrincipalInfo
from zope.publisher.interfaces.http import IHTTPRequest
import ldap.filter
import persistent
import zeit.ldap.connection
import zope.app.appsetup.product
import zope.authentication.interfaces
import zope.component.hooks
import zope.container.contained
import zope.pluggableauth.authentication
import zope.pluggableauth.interfaces
import zope.pluggableauth.plugins.httpplugins
import zope.pluggableauth.plugins.session
import zope.principalregistry.principalregistry
import zope.schema
import zope.security.interfaces


class ILDAPSearchSchema(zope.interface.Interface):
    """A LDAP-specific schema for searching for principals."""

    uid = zope.schema.TextLine(
        title='uid',
        required=False)

    cn = zope.schema.TextLine(
        title='cn',
        required=False)

    givenName = zope.schema.TextLine(
        title='givenName',
        required=False)

    sn = zope.schema.TextLine(
        title='sn',
        required=False)


# copy&paste&tweak from ldappas.authentication
@zope.interface.implementer(
    zope.pluggableauth.interfaces.IAuthenticatorPlugin,
    zope.pluggableauth.interfaces.IQueriableAuthenticator,
    zope.pluggableauth.interfaces.IQuerySchemaSearch)
class LDAPAuthentication(persistent.Persistent,
                         zope.container.contained.Contained):

    adapterName = ''
    searchBases = ['']
    searchScope = ''
    groupsSearchBase = ''
    groupsSearchScope = ''
    loginAttribute = ''
    principalIdPrefix = ''
    idAttribute = ''
    normalizeId = False
    idDomain = ''
    titleAttribute = ''
    descriptionAttribute = ''
    groupIdAttribute = ''

    schema = ILDAPSearchSchema

    def getLDAPAdapter(self):
        return zope.component.queryUtility(
            zeit.ldap.connection.ILDAPAdapter, name=self.adapterName)

    def _searchPrincipal(self, conn, filter, attrs=None):
        res = []
        for base in self.searchBases:
            try:
                res = conn.search(
                    base, self.searchScope, filter=filter, attrs=attrs)
            except NoSuchObject:
                continue
            if res:
                break
        return res

    @CONFIG_CACHE.cache_on_arguments()
    def authenticateCredentials(self, credentials):
        """copy&paste from ldappas to implement custom filter string."""

        if not isinstance(credentials, dict):
            return None
        # wosc: We PATCHED this line:
        # if not ('login' in credentials and 'password' in credentials):
        if not credentials.get('password'):
            return None

        da = self.getLDAPAdapter()
        if da is None:
            return None

        login = credentials['login']
        password = credentials['password']

        # Search for a matching entry.
        try:
            conn = da.connect()
        except ServerDown:
            return None
        # wosc: We PATCHED this line:
        # filter = ldap.filter.filter_format(
        #   '(%s=%s)', (self.loginAttribute, login))
        filter = self.filterQuery.format(
            login=ldap.filter.escape_filter_chars(login))
        res = self._searchPrincipal(conn, filter)
        if len(res) != 1:
            # Search returned no result or too many.
            return None
        dn, entry = res[0]

        # Find the id we'll return.
        id_attr = self.idAttribute
        if id_attr == 'dn':
            id = dn
        elif entry.get(id_attr):
            id = entry[id_attr][0]
        else:
            return None
        id = self.principalIdPrefix + id
        if self.normalizeId:
            id = id.lower()
        if self.idDomain:
            id = id.replace('@%s' % self.idDomain, '')

        # Check authentication.
        try:
            conn = da.connect(dn, password)
        except (ServerDown, InvalidCredentials):
            return None

        return PrincipalInfo(id, **self.getInfoFromEntry(dn, entry))

    def getInfoFromEntry(self, dn, entry):
        return {
            'login': entry[self.loginAttribute][0],
            'title': entry[self.titleAttribute][0],
            'description': entry[self.descriptionAttribute][0],
        }

    @CONFIG_CACHE.cache_on_arguments()
    def principalInfo(self, id):
        """See zope.app.authentication.interfaces.IAuthenticatorPlugin."""
        if not id.startswith(self.principalIdPrefix):
            return None
        internal_id = id[len(self.principalIdPrefix):]
        if self.idDomain:
            internal_id += '@%s' % self.idDomain

        da = self.getLDAPAdapter()
        if da is None:
            return None

        # Search for a matching entry.
        try:
            conn = da.connect()
        except ServerDown:
            return None
        # wosc: PATCHED to support multiple search bases
        filter = '(%s=%s)' % (
            self.idAttribute, ldap.filter.escape_filter_chars(internal_id))
        res = self._searchPrincipal(conn, filter)
        # end PATCH
        if len(res) != 1:
            # Search returned no result or too many.
            return self._groupPrincipalInfo(conn, id, internal_id)
        dn, entry = res[0]

        return PrincipalInfo(id, **self.getInfoFromEntry(dn, entry))

    def _groupPrincipalInfo(self, conn, id, internal_id):
        """Return PrincipalInfo for a group, if it exists.
        """
        if (not self.groupsSearchBase or
                not self.groupsSearchScope or
                not self.groupIdAttribute):
            return None
        filter = ldap.filter.filter_format(
            '(%s=%s)', (self.groupIdAttribute, internal_id))
        try:
            res = conn.search(self.groupsSearchBase, self.groupsSearchScope,
                              filter=filter)
        except NoSuchObject:
            return None
        if len(res) != 1:
            return None
        dn, entry = res[0]
        return PrincipalInfo(id)

    def search(self, query, start=None, batch_size=None):
        """See zope.app.authentication.interfaces.IQuerySchemaSearch."""
        da = self.getLDAPAdapter()
        if da is None:
            return ()
        try:
            conn = da.connect()
        except ServerDown:
            return ()

        # Build the filter based on the query
        filter_elems = []
        for key, value in query.items():
            if not value:
                continue
            filter_elems.append(ldap.filter.filter_format(
                '(%s=*%s*)', (key, value)))
        filter = ''.join(filter_elems)
        if len(filter_elems) > 1:
            filter = '(&%s)' % filter

        if not filter:
            filter = '(objectClass=*)'

        # wosc: PATCHED to support multiple search bases
        res = self._searchPrincipal(conn, filter, attrs=[self.idAttribute])

        prefix = self.principalIdPrefix
        infos = []
        for dn, entry in res:
            try:
                infos.append(prefix + entry[self.idAttribute][0])
            except (KeyError, IndexError):
                pass

        if start is None:
            start = 0
        if batch_size is not None:
            return infos[start:start + batch_size]
        else:
            return infos[start:]


def ldapPluginFactory():
    config = zope.app.appsetup.product.getProductConfiguration(
        'zeit.ldap') or {}
    ldap = LDAPAuthentication()
    ldap.principalIdPrefix = config.get('principal-prefix', 'ldap.')
    ldap.adapterName = 'zeit.ldapconnection'
    ldap.searchBases = config.get('search-base', '').split(' ')
    ldap.searchScope = config.get('search-scope', '')
    ldap.loginAttribute = config.get('login-attribute', '')
    ldap.idAttribute = config.get('id-attribute', '')
    ldap.normalizeId = literal_eval(config.get('normalize-id', 'False'))
    ldap.idDomain = config.get('id-domain')
    ldap.titleAttribute = config.get('title-attribute')
    ldap.descriptionAttribute = config.get('description-attribute')
    ldap.filterQuery = config.get('filter-query', '')
    return ldap


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
            'name': request.headers.get(self.name_header, ''),
        }

    def challenge(self, request):
        # Challenging is already handled by nginx+oauth-proxy.
        return False

    def logout(self, request):
        home = zope.traversing.browser.absoluteURL(
            zope.component.hooks.getSite(), request)
        request.response.redirect(home + self.logout_url)
        return True


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
        ad = zope.component.getUtility(zeit.ldap.azure.IActiveDirectory)
        user = ad.get_user(id)
        if not user:
            return None
        return PrincipalInfo(id, id, user['displayName'], id)

    schema = IAzureSearchSchema

    def search(self, query, start=None, batch_size=None):
        ad = zope.component.getUtility(zeit.ldap.azure.IActiveDirectory)
        result = [
            x['userPrincipalName'] for x in ad.search_users(query['query'])]
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

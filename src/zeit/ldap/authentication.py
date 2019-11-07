from ldapadapter.interfaces import ServerDown, InvalidCredentials, NoSuchObject
from zeit.cms.application import CONFIG_CACHE
import ldap.filter
import ldapadapter.interfaces
import ldapadapter.utility
import persistent
import zope.app.appsetup.product
import zope.pluggableauth.interfaces
import zope.container.contained
import zope.pluggableauth.interfaces
import zope.security.interfaces

ldap_config = (
    zope.app.appsetup.product.getProductConfiguration('zeit.ldap') or {})


class LDAPAdapter(ldapadapter.utility.LDAPAdapter):

    def getServerURL(self):
        # Overwritten so we can pass in a full URI, or even multiple
        # space-separated URIs, see
        # <https://mail.python.org/pipermail/python-ldap/2014q2/003370.html>
        return self.host


def ldapAdapterFactory():
    adapter = LDAPAdapter(
        host=ldap_config.get('host', 'localhost'),
        bindDN=unicode(ldap_config.get('bind-dn', ''), 'utf8'),
        bindPassword=unicode(ldap_config.get('bind-password', ''), 'utf8'))
    return adapter


class PrincipalInfo(object):

    zope.interface.implements(zope.pluggableauth.interfaces.IPrincipalInfo)

    def __init__(self, id, login='', title='', description=''):
        self.id = id
        self.login = login
        self.title = title
        self.description = description

    def __repr__(self):
        return 'PrincipalInfo(%r)' % self.id


# copy&paste&tweak from ldappas.authentication
class LDAPAuthentication(persistent.Persistent,
                         zope.container.contained.Contained):

    zope.interface.implements(
        zope.pluggableauth.interfaces.IAuthenticatorPlugin,
        zope.pluggableauth.interfaces.IQueriableAuthenticator,
        zope.pluggableauth.interfaces.IQuerySchemaSearch)

    adapterName = ''
    searchBase = ''
    searchScope = ''
    groupsSearchBase = ''
    groupsSearchScope = ''
    loginAttribute = ''
    principalIdPrefix = ''
    idAttribute = ''
    titleAttribute = ''
    groupIdAttribute = ''

    def getLDAPAdapter(self):
        return zope.component.queryUtility(
            ldapadapter.interfaces.ILDAPAdapter, name=self.adapterName)

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

        # Check authentication.
        try:
            conn = da.connect(dn, password)
        except (ServerDown, InvalidCredentials):
            return None

        return PrincipalInfo(id, **self.getInfoFromEntry(dn, entry))

    def getInfoFromEntry(self, dn, entry):
        try:
            title = entry[self.titleAttribute][0]
        except (KeyError, IndexError):
            title = dn
        info = {
            'login': entry[self.loginAttribute][0],
            'title': title,
            'description': title,
        }
        try:
            info['description'] = entry['mail'][0]
        except (KeyError, IndexError):
            pass
        return info

    @CONFIG_CACHE.cache_on_arguments()
    def principalInfo(self, id):
        """See zope.app.authentication.interfaces.IAuthenticatorPlugin."""
        if not id.startswith(self.principalIdPrefix):
            return None
        internal_id = id[len(self.principalIdPrefix):]

        da = self.getLDAPAdapter()
        if da is None:
            return None

        # Search for a matching entry.
        try:
            conn = da.connect()
        except ServerDown:
            return None
        # wosc: PATCHED to support multiple search bases
        filter = u'(%s=%s)' % (
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
    ldap = LDAPAuthentication()
    ldap.principalIdPrefix = 'ldap.'
    ldap.adapterName = 'zeit.ldapconnection'
    ldap.searchBases = unicode(
        ldap_config.get('search-base', ''), 'utf8').split(' ')
    ldap.searchScope = unicode(ldap_config.get('search-scope', ''), 'utf8')
    ldap.loginAttribute = unicode(ldap_config.get('login-attribute', ''),
                                  'utf8')
    ldap.idAttribute = unicode(ldap_config.get('id-attribute', ''), 'utf8')
    ldap.titleAttribute = ldap_config.get('title-attribute')
    ldap.filterQuery = unicode(ldap_config.get('filter-query', ''), 'utf8')
    return ldap


class PrincipalRegistryAuthenticator(object):
    """An authentication plugin that looks up users from the PrincipalRegistry.
    """

    zope.interface.implements(
        zope.pluggableauth.interfaces.IAuthenticatorPlugin)

    def authenticateCredentials(self, credentials):
        if credentials is None:
            return None

        prinreg = zope.component.getGlobalSiteManager().getUtility(
            zope.authentication.interfaces.IAuthentication)
        try:
            user = prinreg.getPrincipalByLogin(credentials['login'])
        except KeyError:
            user = None
        if user is None:
            return None
        if not user.validate(credentials['password']):
            return None

        return self._principal_info(user)

    def principalInfo(self, id):
        prinreg = zope.component.getGlobalSiteManager().getUtility(
            zope.authentication.interfaces.IAuthentication)
        user = prinreg.getPrincipal(id)
        if user is None or zope.security.interfaces.IGroup.providedBy(user):
            return None
        return self._principal_info(user)

    def _principal_info(self, user):
        return PrincipalInfo(user.id, user.getLogin(), user.title, '')

from ldapadapter.interfaces import ServerDown, InvalidCredentials, NoSuchObject
from zeit.cms.application import CONFIG_CACHE
import ldap.filter
import ldapadapter.utility
import ldappas.authentication
import zope.app.appsetup.product
import zope.authentication.interfaces
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


class LDAPAuthentication(ldappas.authentication.LDAPAuthentication):

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
        try:
            res = conn.search(self.searchBase, self.searchScope, filter=filter)
        except NoSuchObject:
            return None
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

        return ldappas.authentication.PrincipalInfo(
            id, **self.getInfoFromEntry(dn, entry))

    def getInfoFromEntry(self, dn, entry):
        info = super(LDAPAuthentication, self).getInfoFromEntry(dn, entry)
        try:
            info['description'] = entry['mail'][0]
        except (KeyError, IndexError):
            pass
        return info

    @CONFIG_CACHE.cache_on_arguments()
    def principalInfo(self, id):
        return super(LDAPAuthentication, self).principalInfo(id)


def ldapPluginFactory():
    ldap = LDAPAuthentication()
    ldap.principalIdPrefix = 'ldap.'
    ldap.adapterName = 'zeit.ldapconnection'
    ldap.searchBase = unicode(ldap_config.get('search-base', ''), 'utf8')
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
        return ldappas.authentication.PrincipalInfo(
            user.id, user.getLogin(), user.title, '')

import ldap
import zope.app.appsetup.product
import zope.interface


SCOPES = {
    'base': ldap.SCOPE_BASE,
    'one': ldap.SCOPE_ONELEVEL,
    'sub': ldap.SCOPE_SUBTREE,
}


def convertScope(scope):
    return SCOPES[scope]


class ILDAPAdapter(zope.interface.Interface):
    pass


class ServerDown(Exception):
    """The server doesn't answer"""


class InvalidCredentials(Exception):
    """The credentials are incorrect"""


class NoSuchObject(Exception):
    """The base object doesn't exist"""


@zope.interface.implementer(ILDAPAdapter)
class LDAPAdapter:

    def __init__(self, host='localhost', port=389, useSSL=False,
                 bindDN='', bindPassword=''):
        self.host = host
        self.port = port
        self.useSSL = useSSL
        self.bindDN = bindDN
        self.bindPassword = bindPassword

    def connect(self, dn=None, password=None):
        conn_str = self.getServerURL()
        conn = ldap.initialize(conn_str, bytes_mode=False)
        try:
            conn.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
        except ldap.LDAPError:
            # TODO: fallback on VERSION2 and note that the values
            # are then not utf-8 encoded (charset is implicit (?))
            raise Exception("Server should be LDAP v3")
        # TODO: conn.set_option(OPT_REFERRALS, 1)
        if 'ldaps' in self.host:
            # XXX Disable certificate validation, as I could not make this work
            #   conn.set_option(ldap.OPT_X_TLS_CACERTFILE, '/path/to/file')
            # maybe https://github.com/python-ldap/python-ldap/issues/301 ?
            conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            # https://github.com/python-ldap/python-ldap/issues/55
            conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)

        # Bind the connection to the dn
        if dn is None:
            dn = self.bindDN or ''
            password = self.bindPassword or ''
        try:
            conn.simple_bind_s(dn, password)
        except ldap.SERVER_DOWN:
            raise ServerDown()
        except ldap.INVALID_CREDENTIALS:
            raise InvalidCredentials()

        return LDAPConnection(conn)

    def getServerURL(self):
        # Overwritten so we can pass in a full URI, or even multiple
        # space-separated URIs, see
        # <https://mail.python.org/pipermail/python-ldap/2014q2/003370.html>
        return self.host

    # def getServerURL(self):
    #     """Get the server LDAP URL from the server info."""
    #     proto =  self.useSSL and 'ldaps' or 'ldap'
    #     return '%s://%s:%s' % (proto, self.host, self.port)


class LDAPConnection(object):

    def __init__(self, conn):
        self.conn = conn

    def add(self, dn, entry):
        attrs_list = []
        for key, values in entry.items():
            attrs_list.append((key, values))
        self.conn.add_s(dn, attrs_list)

    def delete(self, dn):
        self.conn.delete_s(dn)

    def modify(self, dn, entry):
        # Get current entry
        res = self.search(dn, 'base')
        if not res:
            raise NoSuchObject(dn)
        cur_dn, cur_entry = res[0]

        mod_list = []
        for key, values in entry.items():
            key = str(key)
            if key in cur_entry:
                if values == []:
                    # TODO fail on rdn removal
                    mod_list.append((ldap.MOD_DELETE, key, None))
                elif cur_entry[key] != values:
                    # TODO treat modrdn
                    mod_list.append((ldap.MOD_REPLACE, key, values))
            else:
                if values != []:
                    mod_list.append((ldap.MOD_ADD, key, values))
        if not mod_list:
            return

        self.conn.modify_s(dn, mod_list)

    def search(self, base, scope='sub', filter='(objectClass=*)',
               attrs=None):
        scope = convertScope(scope)
        try:
            ldap_entries = self.conn.search_s(base, scope, filter, attrs)
        except ldap.NO_SUCH_OBJECT:
            raise NoSuchObject(base)
        # May raise SIZELIMIT_EXCEEDED

        # Convert returned values from utf-8 to unicode.
        results = []
        for dn, entry in ldap_entries:
            for key, values in entry.items():
                # TODO: Can key be non-ascii? Check LDAP spec.
                # FIXME: there may be non-textual binary values.
                try:
                    values[:] = [v.decode('utf-8') for v in values]
                except (UnicodeDecodeError, TypeError):
                    # Not all data is unicode, so decoding does not always work
                    pass
            results.append((dn, entry))
        return results


def ldapAdapterFactory():
    config = zope.app.appsetup.product.getProductConfiguration(
        'zeit.ldap') or {}
    adapter = LDAPAdapter(
        host=config.get('host', 'localhost'),
        bindDN=config.get('bind-dn', ''),
        bindPassword=config.get('bind-password', ''))
    return adapter

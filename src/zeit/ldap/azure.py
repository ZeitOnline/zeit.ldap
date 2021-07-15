import logging
import msal
import persistent
import requests
import zope.interface


log = logging.getLogger(__name__)


class IActiveDirectory(zope.interface.Interface):
    pass


class ITokenCache(zope.interface.Interface):
    pass


@zope.interface.implementer(IActiveDirectory)
class AzureAD:

    graph_url = 'https://graph.microsoft.com/v1.0'

    def __init__(self, tenant_id, client_id, client_secret):
        self.app = msal.ConfidentialClientApplication(
            client_id, client_secret,
            authority='https://login.microsoftonline.com/%s' % tenant_id)

    def _request(self, request, **kw):
        http = requests.Session()
        http.headers['Authorization'] = 'Bearer %s' % self._auth_token()
        method, path = request.split(' ')
        r = getattr(http, method.lower())(self.graph_url + path, **kw)
        if not r.ok:
            r.reason = "%s: %s" % (r.reason, r.text)
        r.raise_for_status()
        return r.json()

    _graph_api_scopes = ['https://graph.microsoft.com/.default']

    def _auth_token(self):
        self.app.token_cache = zope.component.getUtility(ITokenCache)

        # MSAL unfortunately has no info logging, e.g. for "calling refresh"
        token = self.app.acquire_token_silent(
            self._graph_api_scopes, account=None)
        if not token:
            log.info('Retrieving access token with client_secret')
            token = self.app.acquire_token_for_client(self._graph_api_scopes)
        if 'error' in token:
            raise RuntimeError(str(token))
        return token['access_token']

    def get_user(self, upn):
        try:
            return self._request('GET /users/%s' % upn, params={
                '$select': 'displayName,userPrincipalName'
            })
        except requests.exception.RequestException:
            return None


@zope.interface.implementer(IActiveDirectory)
def from_product_config():
    config = zope.app.appsetup.product.getProductConfiguration(
        'zeit.ldap')
    return AzureAD(config['ad-tenant'],
                   config['ad-client-id'], config['ad-client-secret'])


@zope.interface.implementer(ITokenCache)
class PersistentTokenCache(msal.TokenCache, persistent.Persistent):
    """ZODB-based storage for the access- and refresh token."""

    def add(self, *args, **kw):
        super().add(*args, **kw)
        self._p_changed = True

    def modify(self, *args, **kw):
        super().modify(*args, **kw)
        self._p_changed = True

    def __getstate__(self):
        """MSAL sets up a lot of static stuff in init instead of on the class,
        so we restrict the data to pickle to what's actually relevant."""
        return {'_cache': self._cache}

    def __setstate__(self, state):
        self.__init__()
        self.__dict__.update(state)

    def _p_resolveConflict(self, old, commited, newstate):
        """Many places are looking up principals; so to prevent this object
        from being a ConflictError hotspot e.g. when the token expires, we use
        a 'last one wins' strategy instead of forcing a retry -- since we don't
        care which exact access token we store, as long as it's a valid one."""
        return newstate

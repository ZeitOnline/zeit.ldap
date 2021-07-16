import os
import threading
import time
import transaction
import zeit.ldap.azure
import zeit.ldap.testing
import zope.component


class DummyProcess(threading.Thread):

    def __init__(self, db, value, delay=0):
        super().__init__()
        self.db = db
        self.value = value
        self.delay = delay

    def run(self):
        conn = self.db.open()
        root = conn.root()['Application']
        zope.component.hooks.setSite(root)

        cache = zope.component.getUtility(zeit.ldap.azure.ITokenCache)
        time.sleep(self.delay)
        cache._cache['key'] = self.value
        cache._p_changed = True
        try:
            transaction.commit()
        finally:
            conn.close()


class PersistentCacheTest(zeit.ldap.testing.FunctionalTestCase):

    def test_on_conflict_the_last_commit_wins(self):
        # This is the ordering of events we orchestrate here:
        # t1: start
        # t2: start
        # t2: write bar
        # t2: commit
        # t1: write foo
        # t1: commit --> by default, this would raise ConflictError, but our
        # code adjusts this so that it instead overwrites the previous state.

        db = self.layer['zodbDB']
        t1 = DummyProcess(db, 'foo', delay=1)
        t2 = DummyProcess(db, 'bar')
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        transaction.abort()
        cache = zope.component.getUtility(zeit.ldap.azure.ITokenCache)
        self.assertEqual('foo', cache._cache['key'])


class ADIntegrationTest(zeit.ldap.testing.FunctionalTestCase):

    def setUp(self):
        super().setUp()
        gsm = zope.component.getGlobalSiteManager()
        env = os.environ
        self.ad = zeit.ldap.azure.AzureAD(
            env['ZEIT_LDAP_AD_TENANT'],
            env['ZEIT_LDAP_AD_CLIENT_ID'],
            env['ZEIT_LDAP_AD_CLIENT_SECRET'])
        gsm.registerUtility(self.ad)

    def tearDown(self):
        gsm = zope.component.getGlobalSiteManager()
        gsm.unregisterUtility(self.ad, zeit.ldap.azure.IActiveDirectory)
        super().tearDown()

    def test_getPrincipal_sends_query_via_microsoft_graph_api(self):
        auth = zeit.ldap.authentication.AzureADAuthenticator()
        email = os.environ['ZEIT_LDAP_AD_TESTUSER']
        p = auth.principalInfo(email)
        self.assertEqual(p.id, email)

    def test_getPrincipal_returns_none_when_not_found(self):
        auth = zeit.ldap.authentication.AzureADAuthenticator()
        p = auth.principalInfo('nonexistent@zeit.de')
        self.assertEqual(None, p)

    def test_search_returns_list_of_ids(self):
        auth = zeit.ldap.authentication.AzureADAuthenticator()
        email = os.environ['ZEIT_LDAP_AD_TESTUSER']
        (upn,) = auth.search({'query': email.split('@')[0]})
        self.assertEqual(upn, email)

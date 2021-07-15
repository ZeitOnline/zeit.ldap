import zeit.cms.application
import zeit.cms.testing


product_config = """
<product-config zeit.ldap>
  authenticator-plugins principalregistry,ldap
  credentials-plugins xmlrpc-basic-auth
</product-config>
"""

CONFIG_LAYER = zeit.cms.testing.ProductConfigLayer(product_config, bases=(
    zeit.cms.testing.CONFIG_LAYER,))


class CacheLayer(zeit.cms.testing.CacheLayer):

    defaultBases = (CONFIG_LAYER,)

    def setUp(self):
        zeit.cms.application.configure_dogpile_cache(None)


DOGPILE_CACHE_LAYER = CacheLayer()

ZCML_LAYER = zeit.cms.testing.ZCMLLayer(bases=(CONFIG_LAYER,))
ZOPE_LAYER = zeit.cms.testing.ZopeLayer(bases=(ZCML_LAYER,))

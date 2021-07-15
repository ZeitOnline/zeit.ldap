import zeit.cms.generation
import zeit.ldap.azure


def update(root):
    sm = root.getSiteManager()
    zeit.cms.generation.install.installLocalUtility(
        sm,
        zeit.ldap.azure.PersistentTokenCache,
        'azure-token-cache',
        zeit.ldap.azure.ITokenCache)


def evolve(context):
    zeit.cms.generation.do_evolve(context, update)

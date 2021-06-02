from zope.authentication.interfaces import IAuthentication
import zeit.cms.generation


def update(root):
    sm = root.getSiteManager()
    pau = sm.getUtility(IAuthentication)
    assert sm.unregisterUtility(pau, IAuthentication)
    del pau.__parent__[pau.__name__]


def evolve(context):
    zeit.cms.generation.do_evolve(context, update)

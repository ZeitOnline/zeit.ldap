=========
Zeit LDAP
=========

>>> import zope.component.hooks
>>> old_site = zope.component.hooks.getSite()
>>> zope.component.hooks.setSite(getRootFolder())

The `zeit.ldap` package connects the cms to an LDAP or ADS server. A pluggable
authentication utility is registered and configured for using ldap:

>>> import zope.component
>>> import zope.app.security.interfaces
>>> pas = zope.component.getUtility(
...     zope.app.security.interfaces.IAuthentication)
>>> pas
<zope.pluggableauth.authentication.PluggableAuthentication object at 0x...>

The authentication uses the ldap plugin:

>>> pas.authenticatorPlugins
('ldap', 'principalfolder', 'principalregistry')
>>> plugins = list(pas.getAuthenticatorPlugins())
>>> plugins
[('ldap', <zeit.ldap.authentication.LDAPAuthentication object at 0x...>)]
>>> ldap = plugins[0][1]
>>> ldap
<zeit.ldap.authentication.LDAPAuthentication object at 0x...>

So the ldap is basically configured correctly.


Cleanup:

>>> zope.component.hooks.setSite(old_site)

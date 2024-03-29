zeit.ldap changes
=================

.. towncrier release notes start


1.11.0 (2023-08-04)
-------------------

- ZO-2837: Add configurable AD request timeout


1.10.1 (2023-07-26)
-------------------

- Fix brown-bag release


1.10.0 (2023-07-26)
-------------------

- MAINT: Switch to PEP420 namespace packages


1.9.0 (2022-07-14)
------------------

- MAINT: Remove now-unused LDAP codebase


1.8.6 (2022-05-17)
------------------

- MAINT: Initialize Azure connection on use, not on ZCML load time


1.8.5 (2021-10-18)
------------------

- ZO-358: Update function location


1.8.4 (2021-09-27)
------------------

- ZO-216: Explicitly handle AD email adresses as lowercase everywhere


1.8.3 (2021-08-19)
------------------

- OPS-1874: More principal id domain fixes


1.8.2 (2021-07-26)
------------------

- OPS-1929: Handle names with umlauts correctly


1.8.1 (2021-07-19)
------------------

- OPS-1874: More principal id domain fixes


1.8.0 (2021-07-16)
------------------

- OPS-1919: Implement looking up users in AD

- OPS-2058: Implement logout for oidc

- OPS-1873: Make oidc header names configurable


1.7.6 (2021-07-14)
------------------

- OPS-1873: First stab at using oauth-proxy headers for authentication


1.7.5 (2021-07-12)
------------------

- OPS-1874: Fix using email address in principal ids


1.7.4 (2021-07-12)
------------------

- OPS-1874: Support using email addresses as principal ids
  (and cut off the domain name in that case)


1.7.3 (2021-06-07)
------------------

- OPS-1874: Rely on our ldap schema, no need to guard whether fields exist;
  make principal-id prefix configurable


1.7.2 (2021-06-02)
------------------

- OPS-1875: Integrate principal registry seamlessly in PAU


1.7.1 (2021-06-02)
------------------

- OPS-1875: Make Rotterdam UI work with non-persistent PAU


1.7.0 (2021-06-02)
------------------

- OPS-1875: Make PAU non-persistent, as we don't use principalfolder anymore


1.6.0 (2020-04-24)
------------------

- MAINT: Support ldaps with self-signed certs by disabling cert validation


1.5.4 (2019-12-19)
------------------

- MAINT: Be liberal about text/bytes we receive from product config


1.5.3 (2019-12-09)
------------------

- FIX: Don't import test modules in production code


1.5.2 (2019-12-09)
------------------

- ZON-5594: Update to changed vivi API

- FIX: The ldap library now expects unicode, not bytes


1.5.1 (2019-12-06)
------------------

- FIX: Copy forgotten ILDAPSearchSchema from ldappas here


1.5.0 (2019-11-21)
------------------

- ZON-5241: Make Python-3 compatible


1.4.5 (2019-06-05)
------------------

- ZON-4084: Update dependencies to monorepo


1.4.4 (2018-11-28)
------------------

- PERF: Cache authentication result


1.4.3 (2017-07-28)
------------------

- MAINT: Support multiple search bases


1.4.2 (2017-07-28)
------------------

- MAINT: Support configuring multiple ldap servers (they are tried in
  order by the underlying python-ldap/OpenLDAP library)


1.4.1 (2017-07-18)
------------------

- BUG-214: Cache principal info


1.4.0 (2015-11-30)
------------------

- Make filter query configurable (so we can check `memberOf`).


1.3.0 (2015-03-26)
------------------

- Switch from basic auth to login form (DEV-7).


1.2.1 (2011-11-13)
------------------

- Fix brown bag release


1.2.0 (2011-11-13)
------------------

- Return email adress in PrincipalInfo.description


1.1.2 (2010-05-17)
------------------

- Using versions from the ZTK.

1.1.1 (2009-05-15)
------------------

- Alle ``test.py`` nach ``tests.py`` umbenannt.

1.1 (2009-02-05)
----------------

- Leere Passwörter ausschließen und garnicht mehr beim LDAP-Server nachfragen.


1.0 (2008-11-20)
----------------

- Änderungen bzgl. Security-Policy.

0.9.10 (2008-04-18)
-------------------

- First independent release from zeit.cms-core package. No other changes.

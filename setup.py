from setuptools import setup, find_packages


setup(
    name='zeit.ldap',
    version='1.8.2',
    author='gocept, Zeit Online',
    author_email='zon-backend@zeit.de',
    description="Zope3 LDAP interface",
    packages=find_packages('src'),
    package_dir={'': 'src'},
    include_package_data=True,
    zip_safe=False,
    license='BSD',
    namespace_packages=['zeit'],
    install_requires=[
        'msal',
        'python-ldap >= 3.0.0.dev0',
        'persistent',
        'setuptools',
        'transaction',
        'vivi.core',
        'zope.app.securitypolicy',
        'zope.app.zcmlfiles',
        'zope.authentication',
        'zope.container',
        'zope.component',
        'zope.interface',
        'zope.pluggableauth',
        'zope.principalregistry',
        'zope.schema',
        'zope.securitypolicy',
    ],
)

from setuptools import setup, find_packages


setup(
    name='zeit.ldap',
    version='1.9.0',
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
        'persistent',
        'setuptools',
        'transaction',
        'vivi.core',
        'zope.app.appsetup',
        'zope.authentication',
        'zope.component',
        'zope.generations',
        'zope.interface',
        'zope.pluggableauth',
        'zope.principalregistry',
        'zope.publisher',
        'zope.schema',
        'zope.traversing',
    ],
)

from setuptools import setup, find_packages


setup(
    name='zeit.ldap',
    version='1.4.5.dev0',
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
        'ldapadapter>=0.7dev-r82228',
        'ldappas>0.6',
        'setuptools',
        'vivi.core',
        'zope.app.securitypolicy',
        'zope.app.zcmlfiles',
        'zope.securitypolicy',
        'zope.testing',
    ],
)

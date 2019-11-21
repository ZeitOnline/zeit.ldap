from setuptools import setup, find_packages


setup(
    name='zeit.ldap',
    version='1.5.0',
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
        'python-ldap >= 3.0.0.dev0',
        'persistent',
        'setuptools',
        'vivi.core',
        'zope.app.securitypolicy',
        'zope.app.zcmlfiles',
        'zope.container',
        'zope.component',
        'zope.interface',
        'zope.pluggableauth',
        'zope.securitypolicy',
    ],
)

from setuptools import setup, find_packages

setup(
    name='zeit.ldap',
    version='1.2.1dev',
    author='Christian Zagrodnick',
    author_email='cz@gocept.com',
    description="""\
""",
    packages=find_packages('src'),
    package_dir = {'': 'src'},
    include_package_data = True,
    zip_safe=False,
    license='gocept proprietary',
    namespace_packages = ['zeit'],
    install_requires=[
        'ldapadapter>=0.7dev-r82228',
        'ldappas>0.6',
        'setuptools',
        'zeit.cms>1.4',
        'zope.app.securitypolicy',
        'zope.app.zcmlfiles',
        'zope.securitypolicy',
        'zope.testing',
        ],
)

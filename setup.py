from setuptools import setup, find_packages

setup(
    name='zeit.ldap',
    version='0.9.10dev',
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
        'setuptools',
        'zeit.cms>0.9.9',
        'ldapadapter>=0.7dev-r82228',
        'ldappas>0.6',
    ],
    extras_require={
        'test': [
            'zope.securitypolicy',
            'zope.testing',
            'zope.app.zcmlfiles',
            'zope.app.securitypolicy',
        ],
    },
)

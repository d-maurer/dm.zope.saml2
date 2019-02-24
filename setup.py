from os.path import abspath, dirname, join
try:
  # try to use setuptools
  from setuptools import setup
  setupArgs = dict(
      include_package_data=True,
      install_requires=['dm.saml2>=3.2',
                        "dm.zope.schema>=4",
                        "five.formlib", # different versions for Zope 2 and Zope [4]
                        "decorator",
                        "setuptools", # to keep buildout happy
                        ],
      namespace_packages=['dm', 'dm.zope'],
      zip_safe=False,
      )
except ImportError:
  # use distutils
  from distutils import setup
  setupArgs = dict(
    )

cd = abspath(dirname(__file__))
pd = join(cd, 'dm', 'zope', 'saml2')

def pread(filename, base=pd): return open(join(base, filename)).read().rstrip()

setup(name='dm.zope.saml2',
      version=pread('VERSION.txt').split('\n')[0],
      description="Zope 2/Plone extension for SAML2 based Single Sign On: identity, attribute and service providers",
      long_description=pread('README.txt'),
      classifiers=[
#        'Development Status :: 3 - Alpha',
#        "Development Status :: 4 - Beta",
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        "License :: OSI Approved :: GNU General Public License (GPL)",
#        'Framework :: Zope2',
        'Framework :: Zope',
        'Framework :: Zope :: 4',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Topic :: Utilities',
        ],
      author='Dieter Maurer',
      author_email='dieter@handshake.de',
      url='http://pypi.python.org/pypi/dm.zope.saml2',
      packages=['dm', 'dm.zope', 'dm.zope.saml2'],
      keywords='application development zope saml2 sso plone',
      license='ZPL',
      **setupArgs
      )

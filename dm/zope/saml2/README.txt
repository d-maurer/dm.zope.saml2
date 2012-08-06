This package supports SAML2 based SSO (Single Sign-On) for Zope2/Plone
installations.

While it currently supports only a small subset of the
SAML2 standard (simple identity provider, simple service provider
integration and attribute support),
its current functionality is comparable to Plone's OpenId support.



============
Architecture
============


In the SAML2 architecture, a set of distributed authorities (aka entities)
cooperate to provide an overall service. Each authority can take over
one or more roles. Roles are for example "identity provider" (can
identify users), "service provider" (provides some service) and
"attribute provider" (can provide information about users).
Authorities and their roles are described by metadata. The metadata
is exchanged between authorities to allow them to cooperate. SAML2
messages are exchanged to implement the SSO (and other) functionality.

The package currently provides an SAML2 authority,
a simple identity provider, a simple
service provider integration and a simple attribute provider.
All functions are implemented via objects created via the Zope management
interface (ZMI).


Authority
=========

The SAML authority object represents the local SAML authority and
manages the metadata about the foreign authorities cooperating with it.
Its ``metadata`` method (callable via url) returns the metadata
describing the local authority. Foreign authorities are
managed as so called `Entity` objects; their metadata are automatically
updated (based on validity attributes in the metadata), manual update
is supported for special cases.

The objects implementing SAML2 roles
access "their" authority as a (Zope toolkit)
"utility". To make this possible, an SAML authority can only be
created below a (Zope toolkit) site (see the package
``five.localsitemanager`` to learn about sites and how to create one).
(CMF or Plone) portals are sites (in this sense) automatically.
Thus, in a simple setup, you can create an authority object in
a portal (without special actions concerning sites).

There can be at most one SAML authority in a given site.
Nested sites, however, may have their own authority or use that
of a parent site.


Identity Provider
=================

In general, an identity provider has the task to identify users and
to provide assertions about user identities to service providers.

The provided simple identity provider delegates
the first task (identifying users) to a host CMF or Plone portal.
Thereby, it uses the standard portal functionality for login and
authentication; it does not make any assumption about the way
the portal manages its users (and their attributes) and the
details of the authentication process.
Thus, almost any portal can be made into an SAML2 identity provider
by just creating an "Saml simple identity provider" in the portal.

On creation, the identity provider
registers automatically as "identity provider" role
with an SAML authority utility. Creation fails, if this utility either
cannot be located or already knows about an identity provider.

There is a variant identity provider which integrates elemantary
attribute provider functionality (see section "Attribute Support").


Service Provider
================

In general, an SAML2 service provider
provides some kind of (web) service to users and uses SAML2 to get information
about the identities, attributes or access rights for some of its users.
The service provided itself has nothing to do with SAML2; it can be
almost anything (using web technologies).
Only a small part has to do with SAML2: getting information about
users identified and managed externally by other SAML2 authorities.

The simple service provider functionality in this
package  allows either a single portal
or a family of portals sharing a common service provider description
to get authentication information from
an SAML2 identity provider.
It interfaces with the portal[s] via the miniframework 
"pluggable authentication service", used by (e.g.) Plone portals.

In the simple case, the (real) service is implemented by a single portal which
should get authentication information from one or more SAML2
identity providers. This use case is
supported by the creation of an "Saml integrated simple spsso plugin"
in the portal's ``acl_users`` and the activation of its interfaces.

If the SAML2 based authentication replaces the local one, plugins
responsible for local authentication may need to be removed or their
interfaces deactivated. Some integration work is necessary, when local
authentication should coexist with SAML2 based authentication (essentially,
the login form (for local authentication) must be combined with the
identity provider selection (for external authentication)).

In the more complex case, the (real) service is not provided by a single
portal but by a whole family of portals (usually providing the same service
or slightly customized variants of the same service to different user groups)
sharing a common service description with respect to SAML2.
In this case, there is a shared Saml service provider
and each portal has an ``Saml simple spsso plugin (external spsso)``
which work with the shared service provider. In this case, service provider
and plugin communicate via cookies. Therefore, they must get the same cookies.

In fact, the simple case is a variant of the complex one where
service provider and plugin are implemented by the same object.

When a service provider object is created (either standalone or
integrated with the plugin), it registers as "service provider" role
with an SAML authority utility. Creation fails, if this utility
either cannot be located or already knows about a service provider.

The servide provider integration can exhibit user attributes from the
SAML2 assertions as user properties in the portal (user properties
are a standard feature of Plone portals -- to provide addtional
information such as name, email address, ... for a user).


Attribute Support
=================

General SAML2 Attribute Support
-------------------------------

This section sketches the general principles of SAML2 attribute
support. The next section outlines the support provided by this
package.

The SAML2 assertions about a user can include almost arbitrary attributes
to provide additional information (beyond the identity).
Attributes can for example be used to inform a cooperating
SAML authority about the name, the email address, group
membership or special priviledges of a user.

SAML2 attributes are identified by a name format and a (formal, often
unwieldy) name. Optionally, they can have a so called "FriendlyName"
which should be human readable.

SAML2 allows a service provider to define zero or
more "AttributeConsumingService"s. Each "AttributeConsumingService"
is identified by an index (an integer) and contains a sequence
of descriptions for "RequestedAttribute"s.
When the service provider requests authentication for a user, it
can specify for which of its "AttributeConsumingService"s it wants
attribute information.

An SAML2 attribute provider is able to provide attributes for users.
Metadata tells which attributes can be provided.


Attribute Support in this Package
---------------------------------

This package describes attributes by objects, managed in
"Folder"s and identified by (locally unique)
ids. The ids are used as "FriendlyName" in the
SAML metadata and as user property name.
The attribute's SAML2 name format and (formal) name are specified by
attributes of the attribute (describing) object.

Attribute values can be instances of an XML-Schema elementary type
or lists/sequences
thereof (however, Plone may not understand some of those types).

The service provider object is implemented as a "Folder" of
"AttributeConsumingService"s, each "AttributConsumingService"
as a "Folder" of "RequestedAttribute"s. Thus, a service provider
can define various sets of interesting attributes. However, the
standard authentication request requests only the default set.
While there is an authentication method which supports the
specification of the wanted "AttributeConsumingService", it is
likely that this in not yet handled correctly in this version.

The service provider plugin exposes the SAML2 attributes for
a user as standard (for Plone) user properties; the id of
the attribute description is used as user property name.

The current package version
does not have a standalone attribute provider. However, there is
an identity provider variant which has some integrated attribute provider
functionality. It provides attribute information only as part
of authentication requests.
It is implemented as a "Folder" of "Attribute"s which describe
the supported attributes and how their value can be computed.
By default, the id of the attribute description is interpreted
as user property name and its value (for the current user)
used as value for the attribute. Alternatively, the attribute definition
can specify an "Evaluator" -- the name of a method or view called
with parameters *member*, *attr* and *eid* to determine the attribute
value. *member* is the current portal member, *attr* the attribute description
and *eid* the entity identifier who should get the information.


============
Dependencies
============

The package depends on ``Zope2``. It was tested
both with Zope 2.10 and Zope 2.13 (therefore, it is expected to
work with the intermediate versions as well). For Zope versions from
2.12 onward, you must ensure that ``five.formlib`` is installed (as
Zope 2.12 dropped ``zope.formlib`` support from the core; it was
moved into a the separate package ``five.formlib``).

Note that one of the dependencies (``pyxb`` in version 1.1.4) has 
problems to get installed via package managers with Python versions before
2.6. This makes some problems with Zope 2.10 and 2.11. Consult
the dependecies section of ``dm.saml2`` to learn how you can work
around this problem.


============
Installation
============

You must install the code for the package and
ensure that the package's ZCML definitions are interpreted on
Zope startup. In addition, you must ensure that on Zope startup,
the ``xmlsec`` library is initialized
(by calling ``dm.xmlsec.binding.initialize()``).

In order to learn details about ``xmlsec`` signing/verification
failures, you might want to use ``dm.xmlsec.binding.set_error_callback``
to let those details be logged (for details, consult
the ``dm.xmlsec.binding`` documentation).

In the case that you are using ``zc.buildout`` for your Zope2 installation,
then the installation steps can be summarized as follows:

  *  extend the ``eggs`` definition in your ``buildout.cfg``
     by ``dm.zope.saml2`` and (in case you are using Zope2 >= 2.12)
     by ``five.formlib``.

  *  extend the ``zcml`` definition in your ``buildout.cfg``
     by ``dm.zope.saml2``.

  *  ensure ``dm.xmlsec.binding.initialize()`` gets called
     on Zope startup.

The default ``zope.formlib`` support for ``Password`` fields
is very bad (it carefully hides the password on edits
but displays it in clear text on views; it forces
you to reenter the password anew whenever you save the form).
To get decent handling of ``Password`` fields, you may
want to activate the ZCML overrides of package ``dm.zope.schema``.
If you are using ``zc.buildout``. you can achieve this
by extending the ``zcml`` definition in your ``buildout.cfg``
by ``dm.zope.schema-overrides``.

SAML2 stives hard for security. Therefore, it is virtually
impossible to use SAML2 in an identify provider
without digital signatures. The
digital signatures are used to prevent tempering with SAML2 messages
and to authenticate the cooperationg SAML2 authorities.
To effectively use SAML2 for an identity provider, you will need a certificate
and an associated private key such that the authentication assertions
can be properly signed. A certificate can be obtained from a
standard CA (certificate authority); certificates used for HTTPS servers
are usable. Alternatively, it may be possible (this depends
on the SAML2 partners, you want to cooperate with) to generate
your own certificate. "http://www.imacat.idv.tw/tech/sslcerts.html"
describes how you can do this on a Unix-like platform.
Private key and certificate are specified when you create an
SAML authority. For service providers (in contrast to identity providers)
a certificate may not be necessary (this depends on the identity providers
you want to cooperate with; if they (all) accept unsigned authentication
requests, a private key/certificate pair is not necessary).

In case, the interaction between SAML entities poses problems,
the logging facility of ``dm.zope.saml2`` can be helpful.
Logging is enabled by setting the envvar ``SAML2_ENABLE_LOGGING``
to a non empty value. It causes all incoming and outgoing SAML
messages to be logged on level ``INFO``.


History
=======

2.0b2

  Improves control over name identifier formats
  and the creation of name identifiers.

  Adds titles to entities in order to provide a more friendly
  identity provider list.

  Ignores signatures in metadata to avoid a chicken-and-egg problem
  (but this, of course, reduces security).

  Supports authentication request signing (if the identity provider
  requires this).

2.0

  Version 2.0 uses ``dm.xmlsec.binding`` as Python binding to the XML
  security library, rather then the no longer maintained ``pyxmlsec``.
  This drastically facilitates installation.

1.0

  Initial release based on ``pyxmlsec``.


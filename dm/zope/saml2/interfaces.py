# Copyright (C) 2011-2012 by Dr. Dieter Maurer <dieter@handshake.de>
from datetime import timedelta

from zope.interface import Interface, Attribute
from zope.i18nmessageid import MessageFactory
from zope.schema import ASCIILine, Password, Timedelta, Bool, Choice, \
     Timedelta, TextLine, Int, Text, \
     Tuple

from dm.saml2.util import SAML_CLASSES, normalize_class, \
     ATTRNAME_FORMATS, normalize_attrname_format, \
     XSCHEMA_BASE_TYPES, \
     NAMEID_FORMATS

from util import vocab_from_urns

_ = MessageFactory('dm_zope_saml2')

##############################################################################
# role interfaces

class IRole(Interface):
  """An SAML role."""

class IIdpssoRole(IRole):
  """An identity provider."""

class ISpssoRole(IRole):
  """A service provider."""

  def add_attribute_metadata(descriptor):
    """add information about the attribute consuming services to metadata *descriptor*."""

class IApRole(IRole):
  """An attribute provider."""

  def add_attribute_metadata(descriptor):
    """add information about the provided attributes to metadata *descriptor*."""

class IAuthnRole(IRole):
  """An authentication authority."""

class IPdpRole(IRole):
  """An policy decision point."""



##############################################################################
# schemata


class IItemSchema(Interface):
  """the schema describing a base item (elementary Zope object).

  It also has an id, manage outside.
  """
  title = TextLine(
    title=_(u"title_title", u"Title"),
    required=False,
    default=u"",
    )


class ISamlAuthoritySchema(IItemSchema):
  """Parameters configuring an Saml authority (aka entity)."""
  entity_id = ASCIILine(
    title=_(u'entity_id_title', u'Entity id'),
    description=
    _(u'entity_id_description',
      u"""The id identifying this entity/authority.""",),
    required=True,
    )
    
  certificate = ASCIILine(
    title=_(u'certificate_title', u'Certificate'),
    description=
    _(u'certificate_description',
      u"""`clienthome` relative or absolute path to the (DER) file containing the certificate corresponding to 'Private key'.""",),
    required=False,
    )

    
  future_certificate = ASCIILine(
    title=_(u'future_certificate_title', u'Future certificate'),
    description=
    _(u'future_certificate_description',
      u"""`clienthome` relative or absolute path to the (DER) file containing the certificate you plan to use in the near future.
      As other SAML2 authorities rely on your metadata published certificates
      to verify your signatures,
      you cannot simply change your privat/public key pair and publish
      a new certificate: until the other parties had updated their
      metadata for you, they would be unable to verify your signature
      signed with your new private key. This field allows you to publish
      in advance the certificate for a new private key you plan to
      use in the near future. If you ensure a sufficient delay,
      they can be prepared for the key change.
      """,),
    required=False,
    )

  private_key = ASCIILine(
    title=_(u'private_key_title', u'Private key'),
    description=
    _(u'private_key_description',
      u"""`clienthome` relative or absolute path to the (PEM) file containing the private key used for signing/encryption."""
      ),
    required=False,
    )

  private_key_password = Password(
    title=_(u'private_key_password_title', u'Private key password'),
    description=
    _(u'private_key_password_description',
      u"""Password used to encrypt the private key"""),
    required=False
    )

  base_url = ASCIILine(
    title=_(u'base_url_title', u'Base url'),
    description=
    _(u'base_url_description',
      u"""A Zope system is often used via different urls (e.g. direct versus indirectly via a Web server).
      The urls of internal objects change accordingly. The authority generates
      and distributes metadata involving url. These must remain
      reliably and not change inadvertantly. Therefore, the base url is
      not derived automatically from the (varying) urls but specified by this attribute."""),
    required=True,
    )

  metadata_validity = Timedelta(
    title=_(u'metadata_validity_title', u'Metadata validity'),
    description=
    _(u'metadata_validity_description',
      u"""Validity period of generated metadata."""),
    required=True,
    default=timedelta(1), # 1 day
    )


class IBaseAttributeSchema(Interface):
  """base schema describing an attribute.

  Note: it also has an `id` managed outside. The `id` is also used
  as attribute name with which the member is accessed to obtain the
  attribute value.
  """
  title = TextLine(
    title=_(u"attribute_name_title", u"External attribute name"),
    description=_(
      u"attribute_name_description",
      u"The name used to identify the attribute across SAML entities."
      ),
    required=True,
    )

  format = Choice(
    title=_(u"attribute_format_title", u"Name format"),
    description=_(
      u"attribute_format_description",
      u"The name format used to identify this attribute"
      ),
    required=True,
    vocabulary=vocab_from_urns(ATTRNAME_FORMATS),
    default=normalize_attrname_format("unspecified"),
    )

  description = Text(
    title=_(u"attribute_description_title", u"Description"),
    description=_(
      u"attribute_description_description",
      u"Informational (not used internally) description of the attribute",
      ),
    required = False,
    )


class IProvidedAttributeSchema(IBaseAttributeSchema):
  """schema for a provided attribute."""
  type = Choice(
    title=_(u"attribute_type_title", u"Attribute type"),
    description=_(
      u"attribute_type_description",
      u"The XML-schema type of this attribute. It must be an base type. Tuples and lists of base the base type are automatically handled."
      ),
    values=XSCHEMA_BASE_TYPES,
    required=True,
    default=u"string",
    )

  evaluator = ASCIILine(
    title=_(u"attribute_evaluator_title", u"Evaluator"),
    description=_(
      u"attribute_evaluator_description",
      u"Name of a method or view to evaluate/determine the attribute's value. "
      u"It is called with *member*, "
      u"*attr* (providing `IProvidedAttributeSchema`) and *eid* (the entity "
      u"requesting the attribute)."
      ),
    required=False,
    )


class IRequestedAttributeSchema(IBaseAttributeSchema):
  """schema for a requested attribute."""
  required = Bool(
    title=_(u"attribute_required_title", u"Required?"),
    description=_(
      u"attribute_required_description",
      u"Is this attribute required?",
      ),
    required=True,
    default=False,
    )

  is_sequence = Bool(
    title=_(u"attribute_is_sequence_title", u"Sequence?"),
    description=_(
      u"attribute_is_sequence_description",
      u"Has this attribute a sequence as value?"
      ),
    required=True,
    default=False,
    )

  type = Choice(
    title=_(u"requested_attribute_type_title", u"Attribute type"),
    description=_(
      u"requested_attribute_type_description",
      u"The XML-schema type of this attribute or its components. It must be a base type. The previous property controls whether the attribute is a sequence of value of this type or a single value."
      ),
    values=XSCHEMA_BASE_TYPES,
    required=False,
    default=u"string",
    )


class IAttributeConsumingServiceSchema(IItemSchema):
  # override "title" to make it required
  title = TextLine(
    title=_(u"title_title", u"Title"),
    required=True,
    default=u"",
    )

  index = Int(
    title=_(u"attribute_consuming_service_index_title", u"Index"),
    description=_(
      u"attribute_consuming_service_index_description",
      u"Unique integer index identifying this service.",
      ),
    required=True,
    default=0,
    )

  is_default = Bool(
    title=_(u"attribute_consuming_service_is_default_title", u"Default?"),
    description=_(
      u"attribute_consuming_service_is_default_description",
      u"Is this the default service. Only one service must be the default!.",
      ),
    required=True,
    default=False,
    )

  language = ASCIILine(
    title=_(u"attribute_consuming_service_language_title", u"Language"),
    description=_(
      u"attribute_consuming_service_language_description",
      u"The language of the service description (e.g. `en`, `de`, `fr` ...)."
      ),
    required=True,
    default="en",
    )

  description = Text(
    title=_(u"service_description_title", u"Description"),
    description=_(
      u"service_description_description",
      u"Information describing the service.",
      ),
    required = False,
    )

  extends = ASCIILine(
    title=_(u"attribute_consuming_service_extends_title", u"Extends"),
    description=_(
      u"attribute_consuming_service_extends_description",
      u"blank separated sequence of service ids this service extends (not yet supported)"),
    required=False,
    default="",
    )
  

class ISamlRoleSchema(IItemSchema):
  """Common configuration data for SAML role providers.

  See `ISimpleIdpSchema` for the dependence between a role and an
  authority/entity.
  """

  # not yet: assume a global registration
##  authority_designator = ASCIILine(
##    title=_(u'authority_designator_title', u'Authority'),
##    description=
##    _(u'authority_designator_description',
##      u"""path or utility name identifying the SAML authority (= entity) this role belongs to."""),
##    required=False,
##    )


class ISimpleIdpSchema(ISamlRoleSchema):
  """Schema describing the configuration data of a simple identity provider.

  While one can view an identity provider as an SAML2 authority,
  we prefer to associate the authority with an SAML2 entity and
  view the identity provider as its role. This implies a bidirectional
  link between the role and the entity.
  """

  authn_context_class = Choice(
    title=_(u"authn_context_class_title", "Authentication context class"),
    description=_(
      u"auth_context_class_description",
      u"The authentication context class implemented by this identity provider."
      u" The value is likely either `Password` (HTTP username/password authentication) or `PasswordProtectedTransport` (HTTPS username/password authentication)."),
    vocabulary=vocab_from_urns(SAML_CLASSES),
    required=True,
    default=normalize_class("Password"),
    )

  # later
##  idp_discovery_domain = ASCIILine(
##    title=_(u"idp_discovery_domain_title", u"IDP discovery domain"),
##    description=
##    _(u"idp_discovery_domain_description",
##      u"Domain used to determine the applicable identity providers"),
##    required=False,
##    )

##  authn_confirmation_required = Bool(
##    title=_(u"authn_confirmation_required_title", u"authentication confirmation required"),
##    description=
##    _(u"authn_confirmation_required_description",
##      u"whether a confirmation is required before we redirect to a new service provider"),
##    default=False,
##    required=True,
##    )

##  authn_confirmation_validity = Timedelta(
##    title=_(u"authn_confirmation_validity_title", u"authentication confirmation validity"),
##    description=
##    _(u"authn_confirmation_validity_description",
##      u"time period an authentication confirmation for a service provider is valid -- defaults to the current session."),
##    required=False,
##    )

##  max_session_validity = Timedelta(
##    title=_(u"max_session_validity_title", u"maximal session validity"),
##    description=
##    _(u"max_session_validity_description",
##      u"By default, the authentication session is coupled to the browser session; if specified this parameter limits the lifetime of the authentication session. Implementation specifics may limit the duration as well."),
##    required=False,
##    )
    


class ISimpleSpSchema(ISamlRoleSchema):

  default_authn_context_class = Choice(
    title=_(u"default_authn_context_class_title", "Default authentication context class"),
    description=_(
      u"default_auth_context_class_description",
      u"The default authentication context class required by this service provider."
      u" The value is likely either `Password` (HTTP username/password authentication) or `PasswordProtectedTransport` (HTTPS username/password authentication)."),
    vocabulary=vocab_from_urns(SAML_CLASSES),
    required=False,
    )

  cookie_path = ASCIILine(
    title=_(u"cookie_path_title", u"Cookie path"),
    description=_(u"cookie_path_description",
                  u"Path used for all cookies"),
    required=True,
    default="/"
    )

  cookie_domain = ASCIILine(
    title=_(u"cookie_domain_title", u"Cookie domain"),
    description=_(u"cookie_domain_description",
                  u"Domain used for all cookies"),
    required=False,
    )

  session_cookie_name = ASCIILine(
    title=_(u"session_cookie_name_title", u"Session cookie name"),
    description=_(u"session_cookie_name_description",
                  u"The name of the cookie representing the authentication information"),
    required=True,
    default="_saml2_session",
    )

  attribute_cookie_name = ASCIILine(
    title=_(u"attribute_cookie_name_title", u"Attribute cookie name"),
    description=_(u"attribute_cookie_name_description",
                  u"The name of the cookie holding SAML2 attribute information"),
    required=False,
    default="_saml2_attributes",
    )

  encrypt_cookies = Bool(  
    title=_(u"encrypt_cookies_title", u"should cookies be encrypted"),
    description=_(u"encrypt_cookies_description",
                  u"controls whether cookie values are encrypted"),
    required=False,
    default=False,
    )

  nameid_formats = Tuple(
    title=_(u"nameid_formats_title", u"Nameid formats"),
    description=_(u"name_id_formats_description",
                  u"Specifies which nameid formats are acceptable. If left empty, any nameid format is acceptable."
                  ),
    value_type=Choice(
      vocabulary=vocab_from_urns(NAMEID_FORMATS),
      ),
    required=False,
    default=(),
    )

  allow_create = Bool(
    title=_(u"allow_create_title", u"Allow identifier creation"),
    description=_(
      u"allow_create_description",
      u"Allows the identity provider to create/associate a new identifier for the authenticated user."),
    required=False,
    default=True,
    )

  # always
##  wants_assertions_signed = Bool(
##    title=_(u"wants_assertions_signed_title", u"Wants assertions signed?"),
##    description=_(
##      u"wants_assertions_signed_description",
##      u"Indicated whether assertions must be signed?"
##      ),
##    required=False,
##    default=False,
##    )



class ISimpleSpssoPluginSchema(IItemSchema):
  """schema describing a PAS Plugin working together with a SimpleSpsso."""
  idp_cookie_name = ASCIILine(
    title=_(u"idp_cookie_name_title", u"Identity provider cookie name"),
    description=_(u"idp_cookie_name_description",
                  u"The name of the cookie used to remember the user's identity provider"),
    required=False,
    default="idp_id",
    )

  idp_cookie_path = ASCIILine(
    title=_(u"idp_cookie_path_title", u"Identity provider cookie path"),
    description=_(u"idp_cookie_path_description",
                  u"The path of the cookie used to remember the user's identity provider; defaults to the portal"),
    required=False,
    )

  idp_cookie_domain = ASCIILine(
    title=_(u"idp_cookie_domain_title", u"Identity provider cookie domain"),
    description=_(u"idp_cookie_domain_description",
                  u"The domain of the cookie used to remember the user's identity provider"),
    required=False,
    )

  idp_cookie_lifetime = Timedelta(
    title=_(u"idp_cookie_lifetime_title", u"Identity provider cookie lifetime"),
    description=_(u"idp_cookie_lifetime_description",
                  u"The lifetime of the cookie used to remember the user's identity provider. If not specified, this is a session cookie. Example values are `1d` (1 day), `3600s` (1 hour)."),
    required=False,
    default=timedelta(360), # 1 year
    )

  default_idp = ASCIILine(
    title=_(u"default_idp_title", u"Default identity provider"),
    description=_(u"default_idp_description",
                  u"The idp used as default in idp selection"),
    required=False,
    )

  failure_view = ASCIILine(
    title=_(u"failure_view_title", u"Failure view"),
    description=_(u"failure_view_description",
                  u"The view presenting SAML problems."),
    required=True,
    default="@@saml_failure",
    )

  select_idp_view = ASCIILine(
    title=_(u"select_idp_view_title", u"Select idp view"),
    description=_(u"select_idp_view_description",
                  u"The view used to select an identity provider."),
    required=True,
    default="@@saml_select_idp",
    )



class ISimpleApSchema(ISamlRoleSchema):
  """Schema describing the configuration data of a simple attribute provider."""

  # not yet
##  attr_confirmation_required = Bool(
##    title=_(u"attr_confirmation_required_title", u"attribute confirmation required"),
##    description=
##    _(u"attr_confirmation_required_description",
##      u"whether a confirmation is required before we deliver (new) attribute information to a service provider -- defaults to the current session."),
##    default=False,
##    required=True,
##    )

##  attr_confirmation_validity = Timedelta(
##    title=_(u"attr_confirmation_validity_title", u"authentication confirmation validity"),
##    description=
##    _(u"attr_confirmation_validity_description",
##      u"time period an attribute confirmation for a service provider is valid"),
##    required=False,
##    )



class ISamlAuthority(ISamlAuthoritySchema):
  """SAML authority (= entity) interface.

  An SAML authority provides common services for a set of roles.
  It manages the metadata describing itself and that of a set of other SAML
  authorities.
  """
  def register_role_implementor(implementor):
    """register *implementor* as an instance implementing one or more roles for this authority."""

  def unregister_role_implementor(implementor):
    """unregister *implementor*."""

  def export_own_metadata():
    """export this authorities metadata."""

  def export_all_metadata():
    """export the metadata for all authorities known by this authority."""

  def add_entity(entity):
    """add *entity* to the list of managed entities."""

  def list_entities():
    """the list of known entities.

    Note that the entities must not be modified.
    """

  def del_entity(self, eid):
    """delete entity *eid*."""


class ISimpleIdpsso(ISimpleIdpSchema, IIdpssoRole):
  """a simple identity provider."""


class ISimpleSpsso(ISimpleSpSchema, ISpssoRole):
  """a simple service provider."""

  def get_authentication_session(request):
    """return a mapping describing the authentication session (or `None`).

    Return `None`, when there is no authentication session or it is no longer
    valid.

    Otherwise, return a mapping with at least the `user_id` key.
    The `user_id` identifies the user in the form *idp*::*id*
    where *idp* specifies the identity provider which has performed
    the authentication and *id* it the user id it has associated with
    the user for this service provider.

    The mapping may contain additional keys such as
    `authn_context_class` (the authentication context class),
    `authn_time` (when did the authentication took place)
    and `valid_until` (up to which time is the authentication valid).
    """

  def invalidate_authentication_session(request):
    """invalidate all information associated with this user."""

  def get_attributes(request):
    """return a mapping describing the users SAML2 attributes (or `None`).

    Return `None`, when there is no authentication session or it is no longer
    valid.

    Otherwise, return a mapping with attribute values provided by
    the SAML2 identity or attribute provider. The attributes are
    identified by their friendly names.
    """

  def authenticate(idp, ok, fail, authn_context_class=None, passive=False, force=False, acs_index=None, REQUEST=None):
    """request authentication from *idp* and redirect to *ok* or *fail*.

    *acs_index* specifies the index of an attribute consuming service.
    """

  def clear_keys():
    """clear all keys used for signing/verification/encryption/decryption.

    As a consequence, all authentication sessions and attributes
    become invalid.
    """

  def new_key():
    """create a new key used for signing/encryption.

    This causes a new key to be generated - it is used for signing/encryption
    of new values. Some number of older keys are still available for
    verification/decryption. `new_key` may cause the oldest key to be no
    longer used for anything.

    The default number of verification/decryption keys is 5.
    """


class ISimpleAttributeProvider(ISimpleApSchema, IApRole):
  """a simple attribute provider."""



# auxiliary definition to work around Zope's restructuring
try: from zope.lifecycleevent.interfaces import IObjectMovedEvent
except ImportError:
  # old Zope, old location
  from zope.app.container.interfaces import IObjectMovedEvent


###############################################################################
## HttpTransport
class IHttpTransport(Interface):
  """Transport used for SOAP binding.

  Attention: to satisfy the SAML2 security requirements, this
  transport must use an HTTPS client certificate and verify the HTTPS
  server certificate for https connections.
  """

  def open(url, data, headers):
    """post *data* to *url* with *headers* as (some) request headers.

    return a file like object (similar to `urllib.urlopen`).
    """


###############################################################################
## Encryption
class IEncryption(Interface):
  """encryption utility.

  A corresponding utility must be registered for an `SPSSO` role to
  encrypt its cookie values.
  """
  def encrypt(key, value):
    """*value* encrypted by *key*."""

  def decrypt(key, value):
    """*value* decrypted by *key*."""


#############################################################################
## NameID format support
class INameidFormatSupport(Interface):
  """handle name id format extensions."""
  supported = Attribute(u"the sequence of supported name id formats.")

  def make_id(member, sp, ok_create, nid):
    """generate an id for *member*.

    return `None`, if the generation fails, otherwise the id content.

    *sp* is the service provider id. Some formats require ids dependent
    on this id (such as `persistent`).

    *ok_create* is a boolean specifying whether new ids can be created.

    *nid* is a `NameID` instance, partially filled. Its `Format`
    attribute specifies the required nameid format. Some formats
    require the its `SPNameQualifier` be set (e.g. `persistent`).
    """




#############################################################################
## SAML entities
class IEntity(Interface):
  """An entity, a standard SAML authority can work with."""

  id = Attribute(u"the entity id")

  title = Attribute(u"the entities title. "
                    u"Used as human readable entity representation. "
                    u"Defaults to the entity id."
                    )

  def getId():
    """valid Zope id, determined from `id` by escaping."""


#############################################################################
## Relay state management

class IRelayStateStore(Interface):
  """a mapping store used to manage the relay state.

  The store should be able to store picklable objects under
  unique ids. Currently, pairs consisting of a `PyXB` object
  representing an SAML2 request and a relay state,
  and triples consisting of an uuid and 2 urls are stored.
  This may change however in the future.

  The store should be integrated in the Zope transaction
  system. Otherwise, it may not work correctly should
  `ConflictError` arise.

  Possible stores (among others) are an `OOBTree` or the Zope session.
  """

  def __setitem__(id, v):
    """store *v* under *id*."""

  def __getitem__(id):
    """retrieve value associated with *id*."""

  def __delitem__(id):
    """delete value under *id*."""

  def clear():
    """clear the complete store."""


#############################################################################
## Url customization

class IUrlCustomizer(Interface):
  """Interface describing url customizing."""

  def url(obj):
    """the url to be used for *obj*.

    Be careful: the method can be used in contests where the request object
    may not be accessible via acquisition. Therefore, you
    cannot use a standard `IUrl` adapter in an implementation.
    """


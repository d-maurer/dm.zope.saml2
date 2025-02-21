# Copyright (C) 2011-2024 by Dr. Dieter Maurer <dieter.maurer@online.de>
"""Attribute handling.

Attributes occur in SAML2 in idp operations, sp operations and ap operations.
idps and aps provide attributes while sps consume them.
sps organize their attributes into services identified by an integer index.

We essentially have a class describing a single attribute (with a
variant describing a requested attribute), a class managing attributes
(and its variant used for service descriptions) and an attribute
provider class."""
from logging import getLogger

from zope.interface import implementer

from AccessControl import ClassSecurityInfo
from OFS.SimpleItem import SimpleItem
from OFS.Folder import Folder

from dm.zope.schema.schema import SchemaConfigured
from dm.zope.schema.z2.constructor import \
     add_form_factory, SchemaConfiguredZmiAddForm

from dm.saml2.util import normalize_attrname_format, xs_convert_to_xml

from .interfaces import IProvidedAttributeSchema, IRequestedAttributeSchema, \
     IItemSchema, IAttributeConsumingServiceSchema, \
     ISimpleAttributeProvider
from .permission import manage_saml
from .role import Role

logger = getLogger(__name__)


class BaseAttribute(SchemaConfigured, SimpleItem):
  security = ClassSecurityInfo()
  security.declareObjectProtected(manage_saml)

  manage_options = (
    {"label" : "View", "action" : "@@view"},
    {"label" : "Edit", "action" : "@@edit"},
    )


@implementer(IRequestedAttributeSchema)
class RequestedAttribute(BaseAttribute):
  meta_type = "Saml requested attribute"

  SC_SCHEMAS = (IRequestedAttributeSchema,)

  # for backward compatibility
  type = None


@implementer(IProvidedAttributeSchema)
class ProvidedAttribute(BaseAttribute):
  meta_type = "Saml provided attribute"

  SC_SCHEMAS = (IProvidedAttributeSchema,)


@implementer(IItemSchema)
class HomogenousContainer(SchemaConfigured, Folder):
  """Abstract base class for the implementation of homogenous containers.

  Note: `HomogenousContainer` must be sufficiently high up in the `mro`
  to ensure that its `__class_init__` is called. The default
  `__class_init__` (set on `Persistent` by `App.PersistentExtras`)
  does not use cooperative super calling.
  """

  SC_SCHEMAS = (IItemSchema,)

  # to be overridden by derived classes
  CONTENT_TYPE = None

  security=ClassSecurityInfo()
  security.declareObjectProtected(manage_saml)

  manage_options = (
    Folder.manage_options[0],
    {"label" : "View", "action" : "@@view"},
    {"label" : "Edit", "action" : "@@edit"},
    ) + Folder.manage_options[3:]
    

  def all_meta_types(self):
    att = self.CONTENT_TYPE
    if att is None: return ()
    atn = att.__name__
    return dict(
      name=att.meta_type,
      action="add_" + atn,
      permission=manage_saml,
      ),

  @classmethod
  def __class_init__(cls):
    att = cls.CONTENT_TYPE
    if att is not None:
      add_form = add_form_factory(att,
                                  form_class=SchemaConfiguredZmiAddForm
                                  )
      afn = add_form.__name__
      setattr(cls, afn, add_form)
      security = getattr(cls, "security", None)
      if security is None: security = cls.security = ClassSecurityInfo()
      security.declareProtected(manage_saml, afn)
      scls = super(HomogenousContainer, cls)
    elif cls.__name__ == "HomogenousContainer":
      # cannot use the name "HomogenourContainer" here as it is not yet bound
      scls = super(cls, cls)
    else: raise SystemError("class %s has not set `CONTENT_TYPE`" % str(cls))
    ci = scls.__class_init__
    cif = getattr(ci, "__func__", ci)
    cif(cls)


class AttributeContainer(HomogenousContainer):
  """simple container for attribute descriptions."""
  meta_type = "Saml attribute container"

  CONTENT_TYPE = ProvidedAttribute


@implementer(IAttributeConsumingServiceSchema)
class AttributeConsumingService(HomogenousContainer):
  meta_type = "Saml attribute consuming service"

  SC_SCHEMAS = (IAttributeConsumingServiceSchema,)

  CONTENT_TYPE = RequestedAttribute


@implementer(ISimpleAttributeProvider)
class SimpleAttributeProvider(AttributeContainer, Role):
  """Attribute provider.

  For the moment, we only provide attribute support for the `Idpsso`
  but do not handle `AttributeRequest` of our own. This will come later.
  """
  meta_type = "Saml attribute provider"

  SC_SCHEMAS = ISimpleAttributeProvider,

  def _make_attribute_statement(self, target, req, subject, member, index):
    eid = target.eid or req.Issuer.value()
    auth = self._get_authority()
    md = auth.metadata_by_id(eid).get_recent_metadata()
    acs = self._attribute_consuming_service(md, index)
    if acs is None:
      if index is None: return # nothing to do
      logger.error("could not locate acs %d for %s" % (index, eid))
      return "ResourceNotRecognized"
    # catalog our attribute -- should probably be cached
    attrs = {}
    for att in self.objectValues(): attrs[(att.format, att.title)] = att
    # determine the attributes we are ready to provide
    from dm.saml2.pyxb.assertion import AttributeStatement, Attribute, AttributeValue
    av = []
    for ra in acs.RequestedAttribute:
      ran = (ra.NameFormat or normalize_attrname_format("unspecified"), ra.Name)
      d = attrs.get(ran)
      if d is None:
        logger.error("attribute %s requested by %s not found" % (ran, eid))
        continue
      evaluator = d.evaluator
      if evaluator is None: v = member.getProperty(d.getId(), None)
      else: v = self.unrestrictedTraverse(evaluator)(member, d, eid)
      # Plone stupidly converts unicode properties to `str`
      if isinstance(v, bytes) and d.type == "string":
        # convert back to unicode
        from .util import getCharset
        v = v.decode(getCharset(self))
      # potentially, more encodings are necessary
      xv = xs_convert_to_xml(d.type, v, AttributeValue)
      if not isinstance(xv, list): xv = xv,
      aas = dict(
        NameFormat=d.format,
        Name=d.title,
        FriendlyName=ra.FriendlyName or d.getId(),
        )
      att = Attribute(*xv, **aas)
      av.append(att)
    if not av: return
    return AttributeStatement(*av)

  def add_attribute_metadata(self, descriptor):
    from dm.saml2.pyxb.assertion import Attribute
    for ad in self.objectValues():
      descriptor.Attribute.append(
        Attribute(NameFormat=ad.format,
                  Name=ad.title,
                  FriendlyName=ad.id,
                  )
        )

  @staticmethod
  def _attribute_consuming_service(md, index=None):
    """select the effective attribute consuming service or ``None``."""
    for sp in md.SPSSODescriptor: # we expect there is at most one
      for acs in sp.AttributeConsumingService:
        if index is None and acs.isDefault or index == acs.index: break
      else:
        acss = sp.AttributeConsumingService
        if index is None and acss:
          # implement ``E87``
          # we know: no `isDefault` is true
          # take the first ``acs`` without ``isDefault``
          for acs in acss:
            if getattr(acs, "isDefault", None) is None: break
          else: acs = acss[0] # take the first one
        else: acs = None
      if acs is not None: break
    else: acs = None
    return acs

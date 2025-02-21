# Copyright (C) 2011-2024 by Dr. Dieter Maurer <dieter.maurer@online.de>
"""Authority and metadata."""
from tempfile import NamedTemporaryFile
from copy import copy

from persistent import Persistent
from persistent.mapping import PersistentMapping
from Acquisition import Explicit
from AccessControl import ClassSecurityInfo
from BTrees.OOBTree import OOBTree
from OFS.Traversable import path2url

from zope.interface import Interface, implementer
from zope.component import getUtility, ComponentLookupError
from zope.event import notify
from zope.lifecycleevent import ObjectModifiedEvent

from OFS.SimpleItem import SimpleItem
from App.version_txt import getZopeVersion

import dm.xmlsec.binding as xmlsec

from dm.zope.schema.schema import SchemaConfigured, SchemaConfiguredEvolution
from dm.zope.schema.z2.constructor import SchemaConfiguredAddForm
from dm.saml2.metadata import EntityBase, EntityByUrl, \
     EntityMetadata, MetadataRepository, \
     role2element
from dm.saml2.binding import SoapBinding, HttpRedirectBinding, HttpPostBinding
from dm.saml2.pyxb.metadata import EndpointType, IndexedEndpointType
from dm.saml2 import signature
from dm.saml2.util import utcnow

from .interfaces import ISamlAuthority, \
     IIdpssoRole, ISpssoRole, IApRole, IAuthnRole, IPdpRole, \
     INameidFormatSupport, \
     IUrlCustomizer

from .permission import manage_saml
from .util import Volatile, getCharset
from .entity import ManageableEntityMixin, EntityManagerMixin
from .csrf import CsrfAwareOOBTree, csrf_safe_write, csrf_safe


# Note: `EntityByUrl` lacks a way to access the context for signature
#  verification. This is a fundamental problem as we insist on
#  using only a priori known certificates for signature verification.
#  Such information is obviously missing for new entities.
#  Currently, we work around this by not verifying the metadata.
#  Later, we may enhance signature verification by allowing
#  subject certificates issued by a trusted CA.

# Note: we must inform the authority when metadata changes such that
#  it can update the signature verification context. We will
#  use events for this.
class IEntityMetadata(Interface):
  """marker interface."""

# Note: we do not derive from `Persistent` and do not use
#  a persistent list for internal purposes.
#  This is okay as long as we use a persistent storage (as we do).
#  Not using persistent classes here leads to less ZODB loads.
@implementer(IEntityMetadata)
class EntityMetadata(EntityMetadata):
  """extend basic `EntityMetadata` by `ObjectModified` events."""
  def default_validity(self):
    return getUtility(ISamlAuthority).metadata_validity
  default_validity = property(default_validity, lambda self, value: None)

  def fetch_metadata(self, *args, **kw):
    super(EntityMetadata, self).fetch_metadata(*args, **kw)
    notify(ObjectModifiedEvent(self))

  def clear_metadata(self):
    super(EntityMetadata, self).clear_metadata()
    notify(ObjectModifiedEvent(self))

  def _get_metadata_sets(self, *args, **kw):
    rv = super(EntityMetadata, self)._get_metadata_sets(*args, **kw)
    if rv[0]: notify(ObjectModifiedEvent(self))
    return rv


class OwnEntity(ManageableEntityMixin, EntityBase):
  # Note: we cannot pass in the authority as this loses the acquition context
  #  Instead, we access it as utility. This assumes that it is global
  #  (an assumption used elsewhere, too).
  meta_type = "Saml own entity (cannot be deleted or changed)"

  manage_options = ManageableEntityMixin.manage_options[1:]

  protected = True # prevent this entity to be deleted

  # use the authorities entity id as our id
  def id(self):
    try: return getUtility(ISamlAuthority).entity_id
    except ComponentLookupError: return 'invalid_context'
  id = property(id, lambda self, value: None)

  def get_metadata_document(self):
    return self._get_authority()._export_own_metadata()

  def _get_authority(self):
    return getUtility(ISamlAuthority)


@implementer(ISamlAuthority)
class SamlAuthority(SchemaConfiguredEvolution, EntityManagerMixin,
                    SimpleItem, SchemaConfigured, MetadataRepository
                    ):
  """Zope2 implementation for a simple SAML authority.

  The implementation expects the instances to be persistent.

  In order to update internal data, the instance must be notified
  when metadata changes. Event handlers are set up to this effect
  which require that the instance is registered as a local utility
  in the context of the change.
  """
  meta_type = "Saml authority"

  INTERNAL_STORAGE_CLASS = PersistentMapping
  METADATA_STORAGE_CLASS = CsrfAwareOOBTree
  METADATA_CLASS = EntityMetadata

  SC_SCHEMAS = (ISamlAuthority,)

  security = ClassSecurityInfo()

  security.declareObjectProtected(manage_saml)
  security.declareProtected("View", "metadata")

  manage_options = (
    {"label" : "Contents", "action" : "manage_main"},
    {"label" : "View", "action" : "@@view"},
    {"label" : "Edit", "action" : "@@edit"},
    {"label" : "Metadata", "action" : "metadata"},
    ) + SimpleItem.manage_options

##  if getZopeVersion().major >= 4:
##    # we must do this stupidity to work around "https://github.com/zopefoundation/Zope/issues/506"
##    manage_options += dict(label="unworking", action="manage_findForm"),
##    def manage_findForm(self): raise NotImplementedError()


  def __init__(self, **kw):
    SimpleItem.__init__(self)
    SchemaConfigured.__init__(self, **kw)
    MetadataRepository.__init__(self)
    # maps roles to paths to objects implementing the role
    self.roles = self.INTERNAL_STORAGE_CLASS()
    # add entity representing ourselves
    #  must be delayed until `ISamlAuthority` is registered
    #  likely, there are errors when `entityId` is changed
    # self.add_entity(OwnEntity())

  def register_role_implementor(self, implementor):
    # We allow *implementor* to implement more than a single role.
    # Role implementation is indicated by the implementation of the
    #   the respective interface (we may later add a *roles* parameter
    #   to restrict to a subset or allow implementor to restrict).
    md = globals(); roles = self.roles; path = implementor.getPhysicalPath()
    for role in role2element:
      i = md["I" + role.capitalize() + "Role"]
      if i.providedBy(implementor):
        if role in roles:
          raise ValueError("Role %s already registered" % role)
        roles[role] = path
    self._update()

  def unregister_role_implementor(self, implementor):
    roles = self.roles; path = implementor.getPhysicalPath()
    for r, ri in list(roles.items()):
      if ri == path: del roles[r]
    self._update()

  def export_own_metadata(self):
    # return self._export_own_metadata()
    return self.metadata_by_id(self.entity_id).get_recent_metadata().toxml() # return the cached information

  def _update(self):
    """Something important has changed. Invalidate cached data."""
    self.metadata_by_id(self.entity_id).clear_metadata() # recreated on next use
    del self._get_keys_manager()[self.entity_id]


  def _export_own_metadata(self):
    """recompute our own metadata."""
    from dm.saml2.pyxb import metadata
    ed = metadata.EntityDescriptor(
      entityID=self.entity_id,
      validUntil=utcnow() + self.metadata_validity,
      )
    ld = metadata.__dict__
    rno = 0
    for r, p in self.roles.items():
      if r == "ap": continue # for the moment
      i = self.unrestrictedTraverse(p)
      rd = ld[role2element[r]]()
      getattr(ed, rd.__class__.__name__[:-4]).append(rd)
      rno += 1
      for c in (self.certificate, self.future_certificate):
        if c:
          c = _make_absolute(c)
          # build key_info
          from pyxb.bundles.wssplat.ds import KeyInfo, X509Data
          # this assumes the file to contain a (binary) X509v3 certificate
          with open(c, "rb") as f: cert = f.read()
          x509 = X509Data(); x509.X509Certificate = [cert]
          key_info = KeyInfo(); key_info.X509Data = [x509]
          rd.KeyDescriptor.append(
            metadata.KeyDescriptor(key_info, use="signing")
            )
      if hasattr(rd, "NameIDFormat"):
        nifs = INameidFormatSupport(i)
        rd.NameIDFormat = nifs.supported
      # add role specific information -- we do not yet support all roles
      getattr(self, "gen_metadata_" + r)(i, rd)
    if not rno:
      raise ValueError("The authority does not have associated roles; its metadata would violate the saml2 metadata schema")
    return ed.toxml()

  def gen_metadata_sso(self, implementor, rd):
    pass
    # not yet supported
##    rd.ArtifactResolutionService.append(
##      IndexedEndpointType(
##        Binding=SoapBinding,
##        # may want to fix the protocol (to ensure "https" is used)
##        Location="%s/soap" % self._get_url(implementor),
##        index=0,
##        isDefault=True,
##        )
##      )
##    rd.SignleLogoutService.append(
##      EndpointType(
##        Binding=HttpPostBinding,
##        # may want to fix the protocol (to ensure "https" is used)
##        Location="%s/post" % self._get_url(implementor),
##        ))
##    rd.SignleLogoutService.append(
##      EndpointType(
##        Binding=HttpRedirectBinding,
##        # may want to fix the protocol (to ensure "https" is used)
##        Location="%s/redirect" % self._get_url(implementor),
##        ))
        
  def gen_metadata_idpsso(self, implementor, rd):
    self.gen_metadata_sso(implementor, rd)
    rd.SingleSignOnService.append(
      EndpointType(
        Binding=HttpRedirectBinding,
        # may want to fix the protocol (to ensure "https" is used)
        Location="%s/redirect" % self._get_url(implementor),
        ))
    rd.SingleSignOnService.append(
      EndpointType(
        Binding=HttpPostBinding,
        # may want to fix the protocol (to ensure "https" is used)
        Location="%s/post" % self._get_url(implementor),
        ))
    # should we support the artifact resolution binding?
    # might want to specify attributes here -- e.g. when we also implement attributes
    if IApRole.providedBy(implementor):
      implementor.add_attribute_metadata(rd)
        
  def gen_metadata_spsso(self, implementor, rd):
    self.gen_metadata_sso(implementor, rd)
    if implementor.wants_assertions_signed:
      rd.WantsAssertionsSigned = True
      # not safe enough (without signatures)
##    rd.AssertionConsumerService.append(
##      IndexedEndpointType(
##        Binding=HttpRedirectBinding,
##        # may want to fix the protocol (to ensure "https" is used)
##        Location="%s/redirect" % self._get_url(implementor),
##        index=0,
##        isDefault=False,
##        ))
    rd.AssertionConsumerService.append(
      IndexedEndpointType(
        Binding=HttpPostBinding,
        # may want to fix the protocol (to ensure "https" is used)
        Location="%s/post" % self._get_url(implementor),
        index=1,
        isDefault=True,
        ))
    # should we support artifact resolution?
    implementor.add_attribute_metadata(rd)

  def metadata(self, REQUEST):
    """Web access to our metadata."""
    R = REQUEST.response
    md = self.export_own_metadata()
    R.setHeader("Content-Type", "text/xml; charset=utf-8")
    R.setHeader("Cache-Control", "no-cache")
    R.setHeader("Pragma", "no-cache")
    R.setHeader("Expires", "0")
    return md

  def _get_url(self, obj):
    customizer = IUrlCustomizer(self, None)
    if customizer is not None: return customizer.url(obj)
    pp = obj.getPhysicalPath()
    return self.base_url + "/" + path2url(pp[1:])

  ## signature support
  _keys_manager = None

  def _get_keys_manager(self):
    if self._keys_manager is None:
      self._keys_manager = _KeysManager()
      csrf_safe_write(self)
    return self._keys_manager

  def _get_signature_context(self, use):
    vuse = "_v_" + use
    ctx = getattr(self, vuse, None)
    if ctx is None:
      ctx = signature.SignatureContext(self._get_keys_manager())
      setattr(self, vuse, ctx)
    return ctx


  # override entity manager methods to update our signature context
  def _setOb(self, id, entity):
    super(SamlAuthority, self)._setOb(id, entity)
    del self._get_keys_manager()[entity.id]

  # no harm is done, not to invalidate on "_delOb".

  def _to_bytes(self, v):
    return v if isinstance(v, bytes) else v.encode(getCharset(self))


  # work around weakness of `dm.saml2.metadata.MetadataRepository`
  @csrf_safe
  def metadata_by_id(self, eid):
    return super(SamlAuthority, self).metadata_by_id(eid)


# no longer necessary
#InitializeClass(SamlAuthority)


### automatic [un]registration on add/move/delete
def move_handler(o, e):
  try: from zope.component.hooks import getSite
  except ImportError: from zope.app.component.hooks import getSite
  site = getSite()
  if site is None:
    if e.newParent is None:
      # this is likely a global removal - let it succeed
      return
    raise ValueError("need a persistent active site")
  sm = site.getSiteManager()
  if e.oldParent:
    # prevent deletion when there are registered roles
    if o.roles and e.newParent is None:
      raise ValueError(
        "must first delete role implementers",
        ["/".join(p) for p in set(o.roles.values())]
        )
    # unregister
    sm.unregisterUtility(o, provided=ISamlAuthority)
  if e.newParent:
    # register
    # ensure this is a persistent registry
    if not hasattr(sm, "_p_jar"):
      raise ValueError("need a persistent active site")
    sm.registerUtility(o, provided=ISamlAuthority)
    # if `o` is new, we must add its `OwnEntity`
    if e.oldParent is None: # new
      o.add_entity(OwnEntity())


def own_metadata_changed(o, e):
  """subcriber to be informed whenever something changed that affects our own metadata."""
  getUtility(ISamlAuthority)._update()


def signature_context_changed(o, e):
  """subscriber to be informaed whenever the signature context may become invalid."""
  del getUtility(ISamlAuthority)._get_keys_manager()[o.id]


### Customize add form
class AuthorityAddForm(SchemaConfiguredAddForm):
  def customize_fields(self):
    ff_base_url = self.form_fields["base_url"]
    f = copy(ff_base_url.field); f.default = self.request["BASE1"]
    ff_base_url.field = f


### Signature support
# To avoid passing through a signature/verification context, we
#  replace the default contexts in `signature` by objects
#  delegating to the saml authority

class _Delegator(object):
  def sign(self, *args, **kw):
    auth = self._get_authority()._get_signature_context("sign").sign(*args, **kw)

  def sign_binary(self, *args, **kw):
    auth = self._get_authority()._get_signature_context("sign").sign_binary(*args, **kw)

  def verify(self, *args, **kw):
    auth = self._get_authority()._get_signature_context("verify").verify(*args, **kw)

  def verify_binary(self, *args, **kw):
    auth = self._get_authority()._get_signature_context("verify").verify_binary(*args, **kw)

  def _get_authority(self):
    return getUtility(ISamlAuthority)

  # Note: we do not implement "add_key" as in our case, keys should
  #  be added only by the saml authority

signature.default_sign_context = signature.default_verify_context = _Delegator()


class _KeysManager(Explicit):
  """Auxiliary class used as "keys_manager" for ``signature.SignatureContext``."""
  def __init__(self):
    self.eid2volatile_info = CsrfAwareOOBTree()

  def __getitem__(self, eid):
    """the keys associated with entity id *eid*."""
    volatile = self.eid2volatile_info.get(eid)
    info = volatile and volatile.get()
    if info is not None and (info[0] is None or utcnow() <= info[0]):
      return info[1]
    # determine the keys
    auth = self.aq_inner.aq_parent # expected to be the authority
    validUntil = None
    if auth.entity_id == eid:
      # provide our sign key
      keys = xmlsec.Key.load(
        _make_absolute(auth.private_key),
        xmlsec.KeyDataFormatPem,
        # if we have no private key password, pass some value
        #  to prevent an attempt to read it from the terminal
        #  We would like to use the *callback* parameter, but it
        #  does not work currently
        auth.private_key_password and auth._to_bytes(auth.private_key_password) or b"fail",
      ),
    else:
      # foreign entity
      from dm.saml2.metadata import role2element
      md = auth.metadata_by_id(eid)
      rmd = md.get_recent_metadata()
      validUntil = rmd.validUntil
      keys = []
      seen = set()
      for r in role2element:
        for cert in md.get_role_certificates(r, "signing"):
          if cert in seen: continue
          seen.add(cert)
          keys.append(
            xmlsec.Key.loadMemory(cert, xmlsec.KeyDataFormatCertDer, None),
            )
    # refetch `volatile` as a subcriber might have deleted the entry
    volatile = self.eid2volatile_info.get(eid)
    if volatile is None:
      self.eid2volatile_info[eid] = volatile = Volatile()
    volatile.set((validUntil, keys))
    return keys

  def get(self, eid, default=None):
    return self[eid] or default

  def __delitem__(self, eid):
    if eid in self.eid2volatile_info: del self.eid2volatile_info[eid]


def _make_absolute(fn):
  """make *fn* an absolute filename, resolving relative names wrt `clienthome`."""
  from os.path import isabs, join
  if isabs(fn): return fn
  from App.config import getConfiguration
  return join(getConfiguration().clienthome, fn)

# Copyright (C) 2011-2012 by Dr. Dieter Maurer <dieter@handshake.de>
"""The SPSSO role."""
try: from hashlib import sha256 as digest_module
except ImportError: import md5 as digest_module
import hmac
from cPickle import loads, dumps
from zlib import compress, decompress

from zope.interface import implements
from zope.component import getUtility

from AccessControl import ClassSecurityInfo
from Globals import InitializeClass
from OFS.SimpleItem import SimpleItem
from ZTUtils import make_query
from persistent.list import PersistentList

from dm.saml2.util import normalize_class, compare_classes, pyxb_to_datetime, \
     normalize_attrname_format, xs_convert_from_xml, \
     as_utc, utcnow
from dm.zope.schema.schema import SchemaConfigured

from dm.zope.saml2.interfaces import ISimpleSpsso, \
     INameidFormatSupport, \
     IEncryption
from dm.zope.saml2.permission import manage_saml
from dm.zope.saml2.sso import Sso
from dm.zope.saml2.role import Target
from dm.zope.saml2.attribute import \
     HomogenousContainer, AttributeConsumingService


class SimpleSpsso(HomogenousContainer, Sso):
  """Zope 2 implementation of a simple SAML2 Spsso."""

  implements(ISimpleSpsso)

  SC_SCHEMAS = (ISimpleSpsso,)
  CONTENT_TYPE = AttributeConsumingService

  security = ClassSecurityInfo()

  security.declareObjectProtected(manage_saml)
  security.declarePublic("authenticate")

  # as we only support http-post and this requires signing
  wants_assertions_signed = True

  # newly introduced
  nameid_formats = ()
  allow_create = True

  
  def __init__(self, **kw):
    SchemaConfigured.__init__(self, **kw)
    Sso.__init__(self)
    self.__keys = PersistentList()
    self.new_key()

  def authenticate(self, idp, ok, fail, authn_context_class=None, passive=False, force=False, acs_index=None, REQUEST=None):
    """authenticate via *idp*."""
    r = REQUEST or self.REQUEST; R = r.response
    if authn_context_class is None:
      authn_context_class = self.default_authn_context_class
    if authn_context_class is not None:
      authn_context_class = normalize_class(authn_context_class)
    if not force:
      # see whether we have a valid authentication satisfying the requirements
      session = self.get_authentication_session(r)
      if session:
        comparison = (
          authn_context_class is None and -1
          or compare_classes(authn_context_class,
                             session["authn_context_class"]
                             )
          )
        if comparison is not None and comparison <= 0:
          return R.redirect(ok)
    # must authenticate
    from dm.saml2.pyxb.protocol import AuthnRequest, RequestedAuthnContext, \
         NameIDPolicy
    from dm.saml2.pyxb.assertion import AuthnContextClassRef
    req = AuthnRequest(ForceAuthn=force, IsPassive=passive)
    if authn_context_class is not None:
      req.RequestedAuthnContext = RequestedAuthnContext(
        AuthnContextClassRef(authn_context_class)
        )
    if acs_index is not None:
      req.AttributeConsumingServiceIndex = acs_index
    self.customize_authn_request(req)
    relay_state = self.store((req.ID, ok, fail))
    nip = NameIDPolicy(AllowCreate=self.allow_create)
    nifs = INameidFormatSupport(self).supported
    if len(nifs) == 1: nip.Format = nifs[0]
    req.NameIDPolicy = nip
    return self.deliver(
      Target(eid=idp, role="idpsso", endpoint="SingleSignOnService",
             sign_msg_attr="WantAuthnRequestsSigned",
             ),
      None, req, relay_state
      )

  # optionally overridden by derived classes to customize the request
  def customize_authn_request(self, req): pass

  def _process_AuthnStatement(self, subject, s):
    info = dict(
      name_qualifier=subject.NameQualifier,
      nameid_format=subject.Format,
      sp_name_qualifier=subject.SPNameQualifier,
      nameid=subject.value(),
      authn_time=pyxb_to_datetime(as_utc(s.AuthnInstant)),
      valid_until=pyxb_to_datetime(as_utc(s.SessionNotOnOrAfter)),
      session_id=s.SessionIndex,
      authn_context_class=s.AuthnContext.AuthnContextClassRef,
      )
    info["user_id"] = self.format_user_id(info)
    self._set_cookie(self.session_cookie_name, info)

  def _process_AttributeStatement(self, subject, s):
    # build map of known attributes -- we might want to cache this information
    attrs = {}
    for acs in self.objectValues():
      for att in acs.objectValues():
        attrs[(att.format, att.title)] = att
    # now process the attributes
    info = {}
    for att in s.Attribute:
      d = attrs.get(
        (att.NameFormat or normalize_attrname_format("unspecified"),
         att.Name
         ))
      if d is None: continue # do not know this attribute
      info[d.getId()] = xs_convert_from_xml(
        att.AttributeValue, d.is_sequence, d.type
        )
    self._set_cookie(self.attribute_cookie_name, info)



  def get_authentication_session(self, request):
    info = self._get_cookie(request, self.session_cookie_name)
    if info is None: return
    if info["valid_until"] is not None:
      if utcnow() >= info["valid_until"]: return # no longer valid
    return info


  def invalidate_authentication_session(self, request):
    expire = request.response.expireCookie
    params = self._cookie_params()
    expire(self.session_cookie_name, **params)
    expire(self.attribute_cookie_name, **params)


  def get_attributes(self, request):
    # only called when there is an auth session
    #auths = self.get_authentication_session()
    #if auths is None: return
    return self._get_cookie(request, self.attribute_cookie_name)


  def format_user_id(self, info):
    """format user id from dict *info*.

    Almost surely, the `nameid` key will be used.
    To ensure uniqueness, you might need the `name_qualifier`.
    `nameid_format` may allow specific decisions about
    the user id format.

    The primary purpose of this method is customization.
    Be warned however, that changing the format will invalidate
    existing user references.
    """
    return "%(name_qualifier)s::%(nameid)s" % info


  def _cookie_params(self):
    params = dict(path=self.cookie_path, httpOnly=True)
    if self.cookie_domain: params["domain"] = self.cookie_domain
    return params

  def _set_cookie(self, name, info):
    self.REQUEST.response.setCookie(name, self._encode(info),
                                    **self._cookie_params()
                                    )

  def _get_cookie(self, req, name):
    return self._decode(req.cookies.get(name))

  def _encode(self, info):
    """encode *info* for use as integrity protected cookie value."""
    s = self._serialize(info)
    key = self.__keys[0]
    if self.encrypt_cookies:
      value = getUtility(IEncryption).encrypt(key, s)
    else:
      value = hmac.new(key, s, digest_module).digest() + s
    return value.encode("base64").replace("\n", "").replace(" ", "")

  def _decode(self, v):
    """decode cookie value *v* into an info object (or `None`)."""
    if not v: return
    v = v.decode("base64")
    deserialize = self._deserialize
    if self.encrypt_cookies:
      decrypt = getUtility(IEncryption).decrypt
      for k in self.__keys:
        # try to decrypt and deserialize
        try: return deserialize(decrypt(key, v))
        except:
          # probably a wrong key
          pass
      return None # unable to understand the cookie
    else:
      dl = hmac.new("", "", digest_module).digest_size
      digest = v[:dl]; v = v[dl:]
      for k in self.__keys:
        if digest == hmac.new(k, v, digest_module).digest():
          return deserialize(v)
      return None # unable to authenticate

  def _serialize(self, obj):
    return compress(dumps(obj, -1), 9)

  def _deserialize(self, s):
    return loads(decompress(s))

  def add_attribute_metadata(self, descriptor):
    from dm.saml2.pyxb.metadata import AttributeConsumingService, \
         RequestedAttribute, ServiceName, ServiceDescription
    from dm.saml2.pyxb.assertion import Attribute
    # check uniqueness of "index" -- should probably happen earlier
    seen_indexes = set()
    for acs in self.objectValues():
      ads = acs.objectValues()
      if not ads: continue
      index = acs.index
      if index in seen_indexes:
        raise ValueError("duplicate acs index %d for sp %s"
                         % (index, descriptor.getId())
                         )
      seen_indexes.add(index)
      acs_md = AttributeConsumingService(
        ServiceName(acs.title, lang=acs.language),
        index=index, isDefault=acs.is_default,
        )
      if acs.description:
        acs_md.ServiceDescription.append(
          ServiceDescription(asc.description, lang=acs.language)
          )
      for ad in ads:
        acs_md.RequestedAttribute.append(
          RequestedAttribute(
            NameFormat=ad.format,
            Name=ad.title,
            FriendlyName=ad.id,
            isRequired=ad.required,
            )
          )
      descriptor.AttributeConsumingService.append(acs_md)

      

  ## key handling
  KEY_LENGTH = 32
  KEY_NUMBER = 5

  def _create_key(self):
    kl = self.KEY_LENGTH
    try:
      from os import urandom
      bytes = urandom(kl)
    except ImportError: # no "urandom"
      from random import randrange
      bytes = [chr(randrange(256)) for i in range(kl)]
    return "".join(bytes)

  def clear_keys(self):
    del self.__keys[:]

  def new_key(self):
    self.__keys.insert(0, self._create_key())
    del self.__keys[self.KEY_NUMBER:]

InitializeClass(SimpleSpsso)


class StandaloneSimpleSpsso(SimpleSpsso):
  """a `SimpleSpsso` that works with separate plugins.

  Integration is via a (local) utility registration.
  """
  meta_type = "Saml simple spsso (standalone)"




def initialize(context):
  from dm.zope.schema.z2.constructor import add_form_factory, SchemaConfiguredZmiAddForm

  context.registerClass(
    StandaloneSimpleSpsso,
    constructors=(add_form_factory(StandaloneSimpleSpsso, form_class=SchemaConfiguredZmiAddForm),),
    permission=manage_saml,
    )


### automatic [un]registration on add/move/delete
def move_handler(o, e):
  # import will probably need to move for newer Zope
  from zope.app.component.hooks import getSite
  site = getSite()
  if site is None:
      raise ValueError("need a persistent active site")
  sm = site.getSiteManager()
  if e.oldParent:
    # unregister
    sm.unregisterUtility(o, provided=ISimpleSpsso)
  if e.newParent:
    # register
    # ensure this is a persistent registry
    if not hasattr(sm, "_p_jar"):
      raise ValueError("need a persistent active site")
    sm.registerUtility(o, provided=ISimpleSpsso)


class NameidFormatSupport(object):
  """SPSSO name id format support."""
  implements(INameidFormatSupport)

  def __init__(self, context): self.context = context

  def make_id(*args):
    raise NotImplementedError # we only read name ids

  @property
  def supported(self): return self.context.nameid_formats

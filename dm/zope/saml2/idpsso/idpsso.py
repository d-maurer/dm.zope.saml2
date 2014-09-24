# Copyright (C) 2011-2012 by Dr. Dieter Maurer <dieter@handshake.de>
"""The Idpsso implementation."""
from datetime import timedelta

from zope.interface import implements

from AccessControl import ClassSecurityInfo
from OFS.SimpleItem import SimpleItem
from ZTUtils import make_query

from Products.CMFCore.utils import getToolByName

from dm.saml2.uuid import uuid
from dm.saml2.util import compare_classes, normalize_nameid_format, utcnow
from dm.zope.schema.schema import SchemaConfigured
from dm.saml2.pyxb.assertion import AssertionType

from dm.zope.saml2.interfaces import ISimpleIdpsso, IApRole, \
     INameidFormatSupport
from dm.zope.saml2.permission import manage_saml
from dm.zope.saml2.sso import Sso
from dm.zope.saml2.role import Target
from dm.zope.saml2.attribute import SimpleAttributeProvider



# might want to implement as a tool
class SimpleIdpsso(SimpleItem, SchemaConfigured, Sso):
  """Zope2 implementation for a simple SAML Idpsso.

  This is Zope 2, thus we access the request via acquisition.
  Note, that this prevents access via a local utility.
  """
  meta_type = "Saml simple idpsso"

  # how long should authentication responses be valid
  BROWSER_SSO_VALIDITY = timedelta(minutes=5)

  implements(ISimpleIdpsso)

  SC_SCHEMAS = (ISimpleIdpsso,)

  security = ClassSecurityInfo()

  security.declareObjectProtected(manage_saml)
  security.declarePublic("idpsso_logged_in")

  manage_options = (
    {"label" : "View", "action" : "@@view"},
    {"label" : "Edit", "action" : "@@edit"},
    ) + SimpleItem.manage_options

  
  def __init__(self, **kw):
    SchemaConfigured.__init__(self, **kw)
    Sso.__init__(self)


# Standard Plone values -- change, if you need something special
  login_form = "acl_users/credentials_cookie_auth/require_login"
  came_from = "came_from"

  def handle_AuthnRequest(self, req, binding, relay_state):
    mt = getToolByName(self, "portal_membership")
    member = not mt.isAnonymousUser() and mt.getAuthenticatedMember() or None
    if req.IsPassive and not member:
      return self._failedAuthnRequest(req, relay_state, "NoPassive")
    # check for unsupported things -- may want to make this more flexible
    unsupported = []
    if req.Conditions: unsupported.append("Conditions")
    if req.Scoping: unsupported.append("Scoping")
    if unsupported:
      return self._failAuthnRequest(req, relay_state, "RequestUnsupported", ", ".join(unsupported))
    # check requested authn context
    ac = req.RequestedAuthnContext
    if ac:
      if ac.AuthnContextDeclRef:
        # we only support `AuthnContextClassRef`.
        return self._failAuthnRequest(req, relay_state, "RequestUnsupported", "AuthnContextDeclRef")
      if not self._supported_authn_context_class(ac.AuthnContextClassRef):  
        return self._failAuthRequest(req, relay_state, "NoAuthnContext")
    # check name id policy
    nip = req.NameIDPolicy
    if nip and not self._supported_nameid_policy(nip):
      return self._failAuthnRequest(req, relay_state, "InvalidNameIDPolicy")
    if req.ForceAuthn or member is None:
      if req.ForceAuthn: self.acl_users.resetCredentials() # force logout
      # prepare authentication
      skey = self.store((req, relay_state))
      # the view logic gives us an extremely funny "URL" -- explicitely, use
      #  our URL
      # use portal url as base for "login_form"
      self.REQUEST.response.redirect("%s/%s?%s" % (
        getToolByName(self, "portal_url")(), self.login_form,
        make_query({self.came_from : "%s/idpsso_logged_in?%s" % (
          self.absolute_url(), make_query(skey=skey)
          )}),
        ))
    else: return self._okAuthnRequest(req, relay_state, member)


  def _make_authn_response_target(self, req=None):
    if req is None: params = {}
    else:
      params = dict(
        endpoint_index = req.AssertionConsumerServiceIndex,
        binding = req.ProtocolBinding,
        url = req.AssertionConsumerServiceURL,
        )
    return Target(role="spsso",
                  endpoint="AssertionConsumerService",
                  sign_ass_attr="WantAssertionsSigned",
                  **params
                  )

  def _okAuthnRequest(self, req, relay_state, member):
    target = self._make_authn_response_target(req)
    authn_ass = self._make_authn_assertion(target, req, member)
    if not isinstance(authn_ass, AssertionType):
      # this is in fact error information (a string for the moment)
      return self._failAuthnRequest(req, relay_state, authn_ass)
    # we require effectively that `req` is not `None`. This implies
    #  we do not support Idp initiated login.
    if IApRole.providedBy(self):
      attr_st = self._make_attribute_statement(
        target,
        req,
        authn_ass.Subject,
        member,
        req.AttributeConsumingServiceIndex,
        )
      if attr_st is not None: # attributes have been called for
        from dm.saml2.pyxb.assertion import AttributeStatementType
        if not isinstance(attr_st, AttributeStatementType):
          # this is in fact error information (a string for the moment)
          return self._failAuthnRequest(req, relay_state, attr_st)
        authn_ass.AttributeStatement.append(attr_st)
    return self.deliver_success(target, req, (authn_ass,), relay_state)

  def _make_authn_assertion(self, target, req, member):
    from dm.saml2.pyxb.assertion import SubjectType, AuthnStatement, \
         AuthnContext, AuthnContextClassRef
    ass = self.make_assertion()
    subject = self.subject_from_member(member, target, req)
    if not isinstance(subject, SubjectType): return subject # an error
    # add `SubjectConfirmation` and `AudienceRestriction`
    #   as required by the `Web Browser SSO Profile`
    # We might want to put this into a mixin class as
    #   it is helpful for any use of the HTTP-Post binding.
    from dm.saml2.pyxb.assertion import \
         SubjectConfirmation, SubjectConfirmationData, \
         Conditions, AudienceRestriction, Audience
    target.resolve(self._get_authority(), req)
    subject.SubjectConfirmation.append(     
      SubjectConfirmation(
        SubjectConfirmationData(
          NotOnOrAfter=utcnow() + self.BROWSER_SSO_VALIDITY,
          Recipient=target.url,
          InResponseTo=req.ID,
          ),
        Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"
        ))
    cs = ass.Conditions = Conditions()
    cs.AudienceRestriction.append(AudienceRestriction(Audience(target.eid))
      )
    ass.Subject = subject
    # do we need `Conditions`?
    ass.AuthnStatement.append(
      AuthnStatement(
        AuthnContext(
          AuthnContextClassRef(self.authn_context_class)
          ),
        AuthnInstant=ass.IssueInstant, # we cheet here
        )
      )
    return ass


  def _failAuthnRequest(self, req, relay_state, code, msg=None):
    target = self._make_authn_response_target(req)
    return self.deliver_failure(target, req, code, relay_state, msg) 
                    
    
  def idpsso_logged_in(self, skey):
    """return here after a successful login."""
    req, relay_state = self.retrieve(skey)
    member = getToolByName(self, "portal_membership").getAuthenticatedMember()
    return self._okAuthnRequest(req, relay_state, member)

  def _supported_authn_context_class(self, ac):
    # Note: "ac" is a sequence of context class references
    # In principle, we should take into account as well the `Comparison`
    #   However, the processing rules are stupid. Thus, we always assume
    #   "minimum".
    # We support a single context class.
    my_ac = self.authn_context_class
    for cr in ac:
      comparison = compare_classes(cr, my_ac)
      if comparison is not None and comparison <= 0: return True
    return False

  def _supported_nameid_policy(self, nip):
    # we only support "unspecified"
    return not nip.Format or nip.Format in INameidFormatSupport(self).supported

  # ealier versions forgot to perform `Sso` initialization - work around
  class _Upgrader(object):
    """Auxiliary descriptor to ensure we have a `_store` attribute."""
    def __get__(self, inst, cls):
      if inst is None: return cls._store
      id = inst.__dict__
      if "_store" not in id: Sso.__init__(inst)
      return id["_store"]

  _store = _Upgrader()

# no longer necessary
#InitializeClass(SimpleIdpsso)


class SimpleIdpssoAp(SimpleAttributeProvider, SimpleIdpsso):
  """a simple idpsso combined with a simple attribute provider."""
  meta_type = "Saml simple idpsso with integrated attribute provider"

  SC_SCHEMAS = SimpleIdpsso.SC_SCHEMAS + SimpleAttributeProvider.SC_SCHEMAS


def initialize(context):
  from dm.zope.schema.z2.constructor import add_form_factory, SchemaConfiguredZmiAddForm

  for cls in SimpleIdpsso, SimpleIdpssoAp:
    context.registerClass(
      cls,
      constructors=(add_form_factory(cls, form_class=SchemaConfiguredZmiAddForm),),
      permission=manage_saml,
      )


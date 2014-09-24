# Copyright (C) 2011-2012 by Dr. Dieter Maurer <dieter@handshake.de>
"""Generic role infrastructure."""
from logging import getLogger
from os import environ

from zope.interface import implements
from zope.component import getUtility
from BTrees.OOBTree import OOBTree
from ExtensionClass import Base
from Acquisition import Explicit

from dm.saml2.pyxb.protocol import Response
from dm.saml2.pyxb.assertion import NameID, \
     SubjectType, Subject, SubjectConfirmation, \
     ConditionsCheckContext
from dm.saml2.binding import SoapBinding, HttpPostBinding, HttpRedirectBinding
from dm.saml2.util import normalize_nameid_format, utcnow, as_utc
from dm.saml2.binding.util import Store, UnmanagedError, RelayStateManager

from interfaces import ISamlAuthority, IHttpTransport, INameidFormatSupport, \
     IRelayStateStore
from exception import SamlError

logger = getLogger(__name__)


class Store(Base, Store, Explicit):
  """`Store` wrapper facilitating access to the request (and the Zope session)."""


class Role(RelayStateManager):
  """Generic role infrastructure."""
  
  def __init__(self):
    RelayStateManager.__init__(
      self, Store(IRelayStateStore(self, None) or OOBTree())
      )


  def handle_Response(self, rsp, binding, relay_state):
    """handle a positive response."""
    rid, ok, fail = self._resolve_relay_state(relay_state)
    if rid != rsp.InResponseTo:
      raise SamlError("relay state and response to not match: %s" % rid)
    if binding == "redirect":
      raise SamlError("We do not accept responses via redirect (as we do not yet support signatures for redirect")
    context = ResponseContext(
      rsp, binding, self.REQUEST, self._get_authority(),
      )
    # check whether this is a success or failure
    if rsp.Status.StatusCode.Value != rsp.PREFIX + "Success":
      # this is a failure
      logger.error("failed SAML2 request: %s" % rsp.toxml())
      if fail is None: raise SystemError("unsolicited SAML failure response")
      return self.REQUEST.response.redirect(fail)
    # success response
    for ass in rsp.Assertion: self._process_assertion(ass, context)
    return self.REQUEST.response.redirect(ok)

  def _resolve_relay_state(self, relay_state):
    if relay_state:
      try: return self.retrieve(relay_state)
      except UnmanagedError:
        # an unsolicited response
        pass
    raise NotImplementedError("We do not support IDP initiated login")

  def _process_assertion(self, ass, context):
    # ensure we know the issuer -- an exception results, if not
    eid = ass.Issuer.value()
    auth = self._get_authority()
    auth.metadata_by_id(eid)
    if not ass.verified_signature():
      raise SamlError("assertion %s was not signed by the issuer" % ass.ID)
    if not ass.is_valid(context):
      raise SamlError("assertion %s is not valid" % ass.ID)
    if context.binding == "post":
      # check the `SubjectConfirmation` condition of the `Browser SSO profile`
      ok = False
      for sc in ass.Subject.SubjectConfirmation:
        scm = sc.Method
        if scm != "urn:oasis:names:tc:SAML:2.0:cm:bearer":
          # we do not understand the method -- hope, we find one we understand
          continue
        scd = sc.SubjectConfirmationData
        if scd is None: continue # not valid
        if scd.NotOnOrAfter is None or utcnow() >= as_utc(scd.NotOnOrAfter):
          continue # not valid
        if scd.Recipient != context.rsp.Destination:
          continue # not valid
        if scd.InResponseTo != context.rsp.InResponseTo:
          continue # not valid
        if scd.Address and context.zrequest.getClientAddr() != scd.Address:
          continue # not valid
        ok = True
        break
      if not ok:
        raise SamlError("subject confirmation in assertion %s is invalid" % ass.ID)
    subject = ass.Subject.NameID
    for tag in ("Statement", "AuthnStatement", "AuthzDecisionStatement", "AttributeStatement"):
      for s in getattr(ass, tag):
        # process statement -- "AttributeError", if we do not support its type
        getattr(self, "_process_" + tag)(subject, s)



  def deliver_failure(self, target, req, fail, relay_state=None, msg=None):
    rsp = Response()
    rsp.set_status(("Responder", fail), msg)
    return self.deliver(target, rsp, req, relay_state)

  def deliver_success(self, target, req, assertions, relay_state=None):
    rsp = Response()
    rsp.set_success()
    rsp.Assertion = assertions
    return self.deliver(target, rsp, req, relay_state)

  def deliver(self, target, rsp, req, relay_state=None):
    """deliver *rsp* as response to *req* or *req* to *target*.

    If *rsp*, then a response is delivered - in response to *req* (if provided)
    otherwise, *req* is delivered.
    """
    auth = self._get_authority()
    eid = auth.entity_id
    target.resolve(auth, req, rsp)
    msg = rsp or req
    url = target.url
    msg.Destination = url
    msg.Issuer = NameID(eid)
    if target.sign_msg: msg.request_signature()
    if rsp and req: rsp.InResponseTo = req.ID
    if rsp:
      sign = target.sign_ass
      # postprocess assertions
      for ass in getattr(rsp, "Assertion", None):
        # add `Issuer` if it is not present
        if ass.Issuer is None: ass.Issuer = NameID(eid)
        # sign assertion if ours and requested for
        if sign and ass.Issuer.value() == eid: ass.request_signature()
    if logging_enabled:
      logger.info(
        "outgoing saml message to %s via binding %s with relay state %s:\n%s"
        % (msg.Destination,
           target.binding,
           relay_state,
           msg.toxml(root_only=True)
           )
        )
    handler = getattr(
      self,
      (rsp and self.response_handler or self.request_handler)[target.binding]
      )
    return handler(msg, relay_state)

  def _get_authority(self):
    return getUtility(ISamlAuthority)


  def make_assertion(self):
    """an empty assertion, issued by ourself."""
    from dm.saml2.pyxb.assertion import Assertion, NameID, Issuer
    return Assertion(NameID(self._get_authority().entity_id))


  # Note: SAML2 does not provide a good error status for the case
  #  that the subject does not match. We use `SUBJECT_MISMATCH` to let
  #  the status be easliy changed
  SUBJECT_MISMATCH = "UnknownPrinciple"

  def subject_from_member(self, member, target, req):
    """construct a subject description for *member*.

    The description is tailored for *target* and *req*.

    In case of a problem, error information (currently in the form of
    a string) it returned.
    """
    if member is None: return "AuthnFailed"
    auth = self._get_authority(); us = auth.entity_id
    teid = target.eid
    if teid is None: teid = target.eid = req.Issuer.value()
    subject = None
    # if *req* contains a subject, ensure it identifies *member*
    if req.Subject:
      # we only support `NameID` (and get an exception for something else)
      sn = req.Subject.NameID
      # ensure the subject specifies one of our subjects
      if sn.NameQualifier and sn.NameQualifier != us:
        return self.SUBJECT_MISMATCH
      subject = self._subject_from_member(member, sn.SPNameQualifier, sn.Format)
      if not isinstance(subject, SubjectType): return subject
      if sn.value() != subject.NameID.value(): return self.SUBJECT_MISMATCH
    # Note: we make assumptions below which might only hold for
    #  `AuthnRequest`.
    # determine the required name id policy
    unspecified = normalize_nameid_format("unspecified")
    format, sp, ok_create = None, teid, True
    if req.NameIDPolicy:
      nip = req.NameIDPolicy
      format, sp, ok_create = nip.Format, nip.SPNameQualifier, nip.AllowCreate
    if format in (None, unspecified):
      # find a format supported by us and the requester
      rd = target.get_role_descriptor(self._get_authority())
      supported = INameidFormatSupport(self).supported
      for nif in rd.NameIDFormat:
        if nif in supported: format = nif; break
      else:
        if not rd.NameIDFormat or unspecified in rd.NameIDFormat:
          # we can choose the format
          format = supported[0]
        else: return "InvalidNameIDPolicy"
    if sp is None: sp = teid
    return self._subject_from_member(member, sp, format, ok_create)

  def _subject_from_member(self, member, sp, format, ok_create=False):
    format = normalize_nameid_format(format)
    nifs = INameidFormatSupport(self)
    if format not in nifs.supported: return "InvalidNameIDPolicy"
    nid = NameID(NameQualifier=self._get_authority().entity_id, Format=format)
    subject = Subject(
      nid,
      )
    i = nifs.make_id(member, sp, ok_create, nid)
    if i is None: return "InvalidNameIDPolicy" # may not be adequate
    nid._resetContent(); nid.append(i)
    return subject


  # binding handlers
  request_handler = {
    HttpRedirectBinding : "http_redirect",
    HttpPostBinding : "http_post",
    SoapBinding: "soap_request",
    }

  response_handler = {
    HttpRedirectBinding : "http_redirect",
    HttpPostBinding : "http_post",
    SoapBinding: "soap_response",
    }

  def soap_request(self, msg, relay_state):
    from dm.saml2.binding.soap import http_post

    return http_post(getUtility(IHtmlTransport), msg.Destination, msg)

  def soap_response(self, msg, relay_state): return msg

  def http_redirect(self, msg, relay_state):
    from dm.saml2.binding.httpredirect import encode
    url = encode(msg.Destination, msg, relay_state)
    self.REQUEST.response.redirect(url)

  def http_post(self, msg, relay_state):
    from dm.saml2.binding.httppost import encode, as_controls
    return self.unrestrictedTraverse("@@saml_post_template")(
      action=msg.Destination,
      controls=as_controls(encode(msg, relay_state))
      )


class Target(object):
  """auxiliary class to capture destination information."""
  def __init__(self,
               role,     # the role this message is targeted at
               eid=None, # id of the SAML entity receiving the message
               binding=None, # the binding to use
               endpoint=None, # the message is targeted at
               endpoint_index=None, # the index associated with the endpoint
               url=None, # directly specifying the URL.
               sign_ass_attr=None, # role attribute calling for assertions to be signed
               sign_ass=None, # whether assertions should be signed
               sign_msg_attr=None, # role attribute calling for messages to be signed
               sign_msg=None, # whether the message should be signed
               ):
    for k,v in locals().items():
      if k != "self": setattr(self, k, v)

  def resolve(self, auth, req, rsp=None):
    """update the instance to have defined *url* and *binding*.

    Note: There is probably no need for *rsp*.
    """
    __traceback_info__ = self.__dict__
    eid = self.eid
    if eid is None and req is not None: eid = self.eid = req.Issuer.value()
    rd = self.get_role_descriptor(auth)
    if self.url:
      # the url has been directly specified.
      # SAML2 demands to verify that the url indeed belongs to the authority
      #  We try to ensure that be enforcing that the host in url
      #  is identical to the host part of one of the service endpoints
      #  used by this role.
      from dm.saml2.util import child_values
      from dm.saml2.pyxb.metadata import EndpointType
      from urlparse import urlsplit
      target_host = urlsplit(self.url)[1]
      ok = False
      for c in child_values(rd):
        if not hasattr(c, "__iter__"): continue # all endpoints are repeatable
        for ep in c:
          if not isinstance(ep, EndpointType): break # if the first value is not endpoint, none will be
          # should we consider `ResponseLocation` as well?
          if target_host == urlsplit(ep.Location)[1]: ok = True; break
        if ok: break
      if not ok:
        raise SamlError("`%s` does not belong to authority `%s`" % (self.url, eid))
      if self.binding is None:
 	# The request has specified a serice url but no
 	#  protocol binding. Try post (the only binding
 	#  we currently support for authentication responses)
        #  Alternatively, we may try the url to determine
        #  the binding from metadata
        self.binding = HttpPostBinding
    else:
      # `endpoint` must have been specified
      epd = getattr(rd, self.endpoint)
      # we may have more than a single endpoint
      if self.binding:
        # retrict by the requested binding
        epd = [d for d in epd if d.Binding == self.binding]
      epi = self.endpoint_index
      if epi is not None:
        # this requires the endpoints to be indexed endpoints
        epd = [d for d in epd if d.index == epi]
      if len(epd) > 1:
        # we still have more than a single candidate - select on `isDefault`
        epd = [d for d in epd if getattr(d, "isDefault", True)]
      if not epd:
        raise SamlError("no appropriate endpoint found: "
                        + str((eid, self.endpoint, self.binding, self.endpoint_index)))
      epd = epd[0]
      self.binding = epd.Binding
      self.url = rsp is not None and epd.ResponseLocation or epd.Location
    # determine whether we should sign the assertions
    # Note: SAML requires that assertions are signed in the
    #   HTTP-Post binding.
    if not self.sign_ass and self.sign_ass_attr:
      self.sign_ass = getattr(rd, self.sign_ass_attr)
    self.sign_ass = self.sign_ass or self.binding == HttpPostBinding
    # determine whether we should sign the message
    if not self.sign_msg and self.sign_msg_attr:
      self.sign_msg = getattr(rd, self.sign_msg_attr)


  def get_role_descriptor(self, auth):
    return auth.metadata_by_id(self.eid).get_role_descriptor(self.role)


class ResponseContext(ConditionsCheckContext):
  """Auxiliary class to encapsulate the context necessary for response verification."""
  def __init__(self, rsp, binding, zrequest, auth):
    self.rsp = rsp
    self.binding = binding # note: this is "redirect", "post" or "soap"
    self.zrequest = zrequest
    self.auth = auth

  def audience_id(self): return self.auth.entity_id



### automatic [un]registration on add/move/delete
def move_handler(o, e):
  auth = getUtility(ISamlAuthority)
  if e.oldParent:
    # unregister
    auth.unregister_role_implementor(o)
  if e.newParent:
    # register
    auth.register_role_implementor(o)


###### NameID format support

class NameidFormatSupport(object):
  """Default name id format support."""
  implements(INameidFormatSupport)

  def __init__(self, context): self.context = context


  def make_id(self, member, sp, ok_create, nid):
    return self._dispatcher[nid.Format](self, member, sp, ok_create, nid)

  def _unspecified(self, member, *unused): return member.getId()

  _dispatcher = {
    normalize_nameid_format("unspecified"):_unspecified,
    }

  supported = _dispatcher.keys()


######### Logging control
logging_enabled = bool(environ.get("SAML2_ENABLE_LOGGING", ''))

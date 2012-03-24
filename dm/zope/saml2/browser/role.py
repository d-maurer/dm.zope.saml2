# Copyright (C) 2011-2012 by Dr. Dieter Maurer <dieter@handshake.de>
"""Role views."""
from logging import getLogger

from transaction import abort

from Products.Five.browser import BrowserView

from dm.saml2.binding.soap import http_request as soap_request
from dm.saml2.binding.httpredirect import decode as redirect_decode
from dm.saml2.binding.httppost import decode as post_decode
from dm.saml2.pyxb.protocol import CreateFromDocument

from dm.zope.saml2.role import logging_enabled

logger = getLogger(__name__)


class RoleView(BrowserView):
  """Role view.
  
  It implements the various bindings (the incoming part)
  and delegates request processing to its `IRole` context.
  """

  def soap(self):
    """the soap binding."""
    r = self.request
    soap = r.get("SOAPXML") or r["BODY"]
    result, headers, status = soap_request(soap, self._process)
    if status != 200: abort()
    # set response headers
    R = r.response
    R.setHeader("Content-Type", "text/xml; charset=utf-8") # this is SOAP 1.1
    for hn, hv in headers.items(): R.setHeader(hn, hv)
    # should we process the result?
    return result

  def redirect(self):
    """the HTTP redirect binding."""
    r = self.request
    msg, relay_state = redirect_decode("%s?%s" % (r["URL"], r["QUERY_STRING"]))
    return self._process(msg, binding="redirect", relay_state=relay_state)

  def post(self):
    msg, relay_state = post_decode(self.request.form)
    return self._process(msg, binding="post", relay_state=relay_state)

  # we do not yet support "artifact"


  def _process(self, saml, **kw):
    __traceback_info__ = saml
    # Determine our url: due to a bug in the view machinery, the
    #  last component can be repeated -- remove, if necessary
    r = self.request
    url1, url2 = r["URL1"], r["URL"]
    suff = url2[len(url1):]
    url = not url1.endswith(suff) and url2 or url1
    if logging_enabled:
      logger.info(
        "incoming saml message at %s via binding %s with relay state %s:\n%s"
        % (url,
           kw.get("bindung"),
           kw.get("relay_state"),
           saml
           )
        )
    saml = CreateFromDocument(saml)
    # If there are signatures they have been verified by now
    #  but we have not yet checked that there are indeed signatures
    # verify destination; set, if not available
    if saml.Destination and saml.Destination != url:
      raise SamlError("destination mismatch")
    saml.Destination = url # necessary for further checks
    return getattr(
      self.context, "handle_" + saml._element().name().localName()
      )(saml, **kw)

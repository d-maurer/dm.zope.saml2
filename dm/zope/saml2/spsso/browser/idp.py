# Copyright (C) 2011-2012 by Dr. Dieter Maurer <dieter@handshake.de>
"""Idp related views."""
from urllib import quote, unquote

from zope.schema import Choice
from zope.formlib.form import Fields, action

from Products.CMFCore.utils import getToolByName

from dm.zope.schema.z2.form import PageForm

from dm.zope.saml2.interfaces import _


class SelectIdp(PageForm):
  label = _(u"select_idp_title", u"Select your identity provider.")

  def __init__(self, context, request):
    self.form_fields = Fields(
      Choice(__name__=u"idp",
             title=_(u"identity_provider", u"Your identity provider"),
             values=context.list_idps(),
             default=context.default_idp,
             required=True,
             )
      )
    super(SelectIdp, self).__init__(context, request)
    # ensure, we do not lose "came_from" -- this should be easier!
    #  "dm.zope.schema" should provide a `Hidden` field
    request.response.setCookie("came_from", quote(request["came_from"]))

  @action(_(u"login", u"login"))
  def login(self, action, data):
    c = self.context; r = self.request; R = r.response
    idp = data["idp"]
    c.set_idp_cookie(idp)
    R.expireCookie("came_from")
    return self.context.authn(idp, unquote(r["came_from"]))


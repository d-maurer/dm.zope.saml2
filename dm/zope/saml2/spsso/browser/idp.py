# Copyright (C) 2011-2012 by Dr. Dieter Maurer <dieter@handshake.de>
"""Idp related views."""
from urllib import quote, unquote

from zope.schema import Choice, ASCIILine
from zope.formlib.form import Fields, action
from zope.schema.vocabulary import SimpleVocabulary, SimpleTerm

from Products.CMFCore.utils import getToolByName

from dm.zope.schema.z2.form import PageForm
from dm.zope.schema.widget import GenericTextWidget, make_hidden

from dm.zope.saml2.interfaces import _


class SelectIdp(PageForm):
  label = _(u"select_idp_title", u"Select your identity provider.")

  def __init__(self, context, request):

    def title(eid):
      """the title of entity *eid* (or *eid* itself)."""
      return getattr(context.get_entity(eid), "title", eid)

    self.form_fields = Fields(
      Choice(
        __name__=u"idp",
        title=_(u"identity_provider", u"Your identity provider"),
        vocabulary=SimpleVocabulary(
          tuple(SimpleTerm(eid, title(eid)) for eid in context.list_idps())
          ),
        default=context.default_idp,
        required=True,
        ),
      ASCIILine(
        __name__=u"came_from",
        default=request.get("came_from", ""),
        required=False,
        ),
      )
    super(SelectIdp, self).__init__(context, request)
    self.form_fields["came_from"].custom_widget = make_hidden(GenericTextWidget)

  @action(_(u"login", u"login"))
  def login(self, action, data):
    c = self.context
    idp = data["idp"]
    c.set_idp_cookie(idp)
    return self.context.authn(idp, data["came_from"])


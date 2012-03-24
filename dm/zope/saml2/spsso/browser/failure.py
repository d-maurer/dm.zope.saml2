# Copyright (C) 2011-2012 by Dr. Dieter Maurer <dieter@handshake.de>
from Products.Five.browser import BrowserView
from Products.CMFCore.utils import getToolByName

from Products.statusmessages.interfaces import IStatusMessage

from dm.zope.saml2.interfaces import _


class Failure(BrowserView):
  def __call__(self):
    r = self.request
    IStatusMessage(r).addStatusMessage(_(u"SAML request failed"))
    r.response.redirect(getToolByName(self.context, "portal_url")())


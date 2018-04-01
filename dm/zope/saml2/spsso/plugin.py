# Copyright (C) 2011-2012 by Dr. Dieter Maurer <dieter@handshake.de>
"""PAS plugins for SAML2 based authentication (Spsso)."""
from datetime import datetime

from zope.interface import implements

from AccessControl import ClassSecurityInfo
from ZTUtils import make_query
from Globals import InitializeClass

from Products.CMFCore.utils import getToolByName
from Products.PluggableAuthService.interfaces.plugins \
        import IExtractionPlugin, IAuthenticationPlugin, \
                ICredentialsResetPlugin, IChallengePlugin, \
                IPropertiesPlugin
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements
from Products.PluggableAuthService.PluggableAuthService import \
     registerMultiPlugin

from dm.zope.schema.schema import SchemaConfigured

from dm.zope.saml2.permission import manage_saml
from dm.zope.saml2.util import datetime_rfc822
from dm.zope.saml2.interfaces import ISimpleSpssoPluginSchema, \
     ISimpleSpsso

from spsso import SimpleSpsso


class DetachedSimpleSpssoPlugin(BasePlugin, SchemaConfigured):
  """Spsso plugin working with a separate `Spsso`."""

  meta_type = "Saml detached simple spsso plugin (with standalone spsso)."

  security = ClassSecurityInfo()
  security.declareObjectProtected(manage_saml)
  security.declarePublic("login")

  implements(ISimpleSpssoPluginSchema)

  manage_options = (
    {"label" : "View", "action" : "@@view"},
    {"label" : "Edit", "action" : "@@edit"},
    ) + BasePlugin.manage_options

  SC_SCHEMAS = (ISimpleSpssoPluginSchema,)

  def extractCredentials(self, request):
    return dict(saml=True) # may not play well with caching

  def authenticateCredentials(self, credentials):
    if not credentials.get("saml"): return
    spsso = self.get_spsso()
    info = spsso.get_authentication_session(self.REQUEST)
    if info is not None:
      uid = info["user_id"]
      return (uid, uid)

  def resetCredentials(self, request, response):
    self.get_spsso().invalidate_authentication_session(request)


  def challenge(self, request, response):
    url = self.absolute_url()
    came_from = "%s?%s" % (
      request["ACTUAL_URL"], request.get("QUERY_STRING","")
      )
    idp = self.determine_idp()
    if idp:
      # we know the idp -- perform authentication
      #  Note: we must do a redirect to `authenticate` as it
      #  requires a successful transaction commit.
      #  The current transaction, however, will be aborted
      spsso = self.get_spsso()
      url = "%s/authenticate?%s" % (
        spsso.absolute_url(),
        make_query(idp=idp, ok=came_from, fail=url + "/" + self.failure_view)
        )
    else:
      url = "%s/%s?%s" % (
          url, self.select_idp_view, make_query(came_from=came_from)
        )
    # we hope the protocol chooser will ensure higher up user folders
    #  will still be able to get their chance
    #  otherwise, we will need to override "response._unauthorized"
    #  rather than performing the redirect here ourselves.
    response.redirect(url, lock=True)
    return True

  def authn(self, idp, came_from, fail=None, authn_context_class=None, passive=False, force=False, ap_index=None):
    idp = idp or self.determine_idp()
    if not idp: raise ValueError("Identity provider should not be determined")
    return self.get_spsso().authenticate(
      idp,
      came_from,
      fail or self.absolute_url() + "/" + self.failure_view,
      authn_context_class,
      passive,
      force,
      ap_index,
      self.REQUEST,
      )

  def login(self):
    """explicit login request."""
    r = self.REQUEST; purl = getToolByName(self, "portal_url")()
    came_from = r.get("came_from") or r.get("HTTP_REFERER") or purl
    idp = self.determine_idp()
    if idp:
      return self.authn(idp, came_from,
                        self.absolute_url() + "/" + self.failure_view
                        )
    else:
      r.response.redirect("%s/%s?%s" % (
        self.absolute_url(),
        self.select_idp_view,
        make_query(came_from=came_from)
        ))

  def getPropertiesForUser(self, user, request=None):
    info = self.get_spsso().get_attributes(self.REQUEST) or {}
    # the stupid Plone is unable to handle unicode properties
    #  must encode them
    from ..util import getCharset
    charset = getCharset(self)
    for k,v in info.items():
      if isinstance(v, unicode): info[k] = v.encode(charset)
      elif v and isinstance(v, (tuple, list)) and isinstance(v[0], unicode):
        info[k] = [c.encode(charset) for c in v]
    # more conversion might need to become necessary
    return info

  def determine_idp(self):
    r = self.REQUEST
    idp_cn = self.idp_cookie_name
    idp = idp_cn and r.get(idp_cn)
    if not idp:
      idps = self.list_idps()
      if len(idps) == 1: idp = idps[0]
    if idp and idp_cn not in r.cookies:
      self.set_idp_cookie(idp)
    return idp or None

  def list_idps(self):
    auth = self.get_spsso()._get_authority()
    idps = []
    for e in auth.list_entities():
      md = auth.metadata_by_id(e.id).get_recent_metadata()
      if md.IDPSSODescriptor: idps.append(e.id)
    return idps

  def get_spsso(self):
    return ISimpleSpsso(self)

  def get_entity(self, eid):
    """return the entity specified by entity id *eid*."""
    return self.get_spsso()._get_authority().get_entity(eid)

  def set_idp_cookie(self, idp):
    cn = self.idp_cookie_name
    if not cn: return
    cp = self.idp_cookie_path
    if not cp:
      # default is the portal path
      cp = "/" + getToolByName(self, "portal_url").getPortalObject().absolute_url(True)
    cparams = dict(path=cp, httpOnly=True)
    if self.idp_cookie_lifetime:
      expires = datetime.now() + self.idp_cookie_lifetime
      # convert to rfc822
      cparams["expires"] = datetime_rfc822(expires)
    if self.idp_cookie_domain:
      cparams["domain"] = self.idp_cookie_domain
    self.REQUEST.response.setCookie(cn, idp, **cparams)


InitializeClass(DetachedSimpleSpssoPlugin)

classImplements(DetachedSimpleSpssoPlugin,
                IExtractionPlugin, IAuthenticationPlugin,
                ICredentialsResetPlugin, IChallengePlugin,
                IPropertiesPlugin,
                )
    
  
class IntegratedSimpleSpssoPlugin(SimpleSpsso, DetachedSimpleSpssoPlugin):
  meta_type = "Saml integrated simple spsso plugin (integrated spsso)."

  SC_SCHEMAS = (ISimpleSpssoPluginSchema, ISimpleSpsso,)

  manage_options = (
    SimpleSpsso.manage_options[0],
    ) + DetachedSimpleSpssoPlugin.manage_options




def initialize(context):
  from dm.zope.schema.z2.constructor import add_form_factory, SchemaConfiguredZmiAddForm

  registerMultiPlugin(DetachedSimpleSpssoPlugin.meta_type)
  registerMultiPlugin(IntegratedSimpleSpssoPlugin.meta_type)

  context.registerClass(
    DetachedSimpleSpssoPlugin,
    constructors=(add_form_factory(DetachedSimpleSpssoPlugin, form_class=SchemaConfiguredZmiAddForm),),
    permission=manage_saml,
    visibility=None,
    )

  context.registerClass(
    IntegratedSimpleSpssoPlugin,
    constructors=(add_form_factory(IntegratedSimpleSpssoPlugin, form_class=SchemaConfiguredZmiAddForm),),
    permission=manage_saml,
    visibility=None,
    )
  

def default_plugin_spsso_adapter(plugin):
  return getUtility(ISimpleSpsso)


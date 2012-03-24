"""Entity management.

We assume that our entities are schema configured and implement `IEntity`.
"""
from urllib import quote, unquote

from zope.interface import Interface, implements
from zope.schema import URI

from OFS.SimpleItem import SimpleItem
from OFS.ObjectManager import ObjectManager, IFAwareObjectManager
from AccessControl import ClassSecurityInfo

from dm.zope.schema.schema import SchemaConfigured

from dm.saml2.metadata import EntityByUrl

from dm.zope.saml2.interfaces import _, IEntity
from dm.zope.saml2.permission import manage_saml


class ManageableEntityMixin(SchemaConfigured, SimpleItem):
  """Mixin class to provide `SchemaConfigured` based manageability.

  Note: We expect the entity class to be configurable by the
  schema only.

  The instances expect to be managed inside a `MetadataRepository`.
  """
  implements(IEntity)

  manage_options = (
    {"label" : "Edit", "action" : "@@edit"},
    {"label" : "Metadata", "action" : "metadata"},
    {"label" : "Update", "action" : "@@update"},
    ) + SimpleItem.manage_options
    

  security = ClassSecurityInfo()
  security.declareObjectProtected(manage_saml)

  def metadata(self, REQUEST):
    """Web access to metadata."""
    md = self.aq_inner.aq_parent.metadata_by_id(self.id).get_recent_metadata().toxml()
    R = REQUEST.response
    R.setHeader("Content-Type", "text/xml; charset=utf-8")
    R.setHeader("Cache-Control", "no-cache")
    R.setHeader("Pragma", "no-cache")
    R.setHeader("Expires", "0")
    return md
    
    
  # override `SimpleItem` methods to get our id attribute to be named `id`
  def getId(self):
    # must return a quoted id as entity ids may contain characters
    #  forbidden in Zope ids
    return _quote(self.id)

  def _setId(self, id): self.id = id


class IEntityByUrl(IEntity):
  url = URI(
    title=_(u"entity_url_title", "Url"),
    description=_(
      u"entity_url_description",
      u"Url from which this entities' metadata can be fetched.",
      ),
    required=True,
    )



class EntityByUrl(ManageableEntityMixin, EntityByUrl):
  implements(IEntityByUrl)

  meta_type = "Saml2 entity defined by metadata providing url"

  SC_SCHEMAS = (IEntityByUrl,)

  @property
  def title(self): return self.url


class EntityManagerMixin(IFAwareObjectManager, ObjectManager):
  """mixin class to manage managable entities.

  We assume to be part of a `MetadataRepository`.

  Note: we use quoted ids for the managed entities as the entity ids
    themselves can contain characters not allowed in Zope ids.
  """
  _product_interfaces = (IEntity,)

  def _setOb(self, id, entity):
    # *id* may or may not be quoted -- we ignore it altogether
    self.add_entity(entity)

  def _getOb(self, id, default=None):
    e = self.get_entity(_unquote(id), default)
    if e is not default: e = e.__of__(self) # acquisition wrap
    return e

  def _delOb(self, id):
    e = self.get_entity(_unquote(id))
    if e is None: return
    if getattr(e, "protected", False):
      raise TypeError(_(u"protected_entity_deletion",
                        u"Cannot delete a protected entity")
                      )
    self.del_entity(e.id)

  def __getitem__(self, k):
    e = self._getOb(k)
    if e is None: raise KeyError(k)
    return e

  def objectIds(self, spec=None):
    assert spec is None
    return [_quote(e.id) for e in self.list_entities()]

  def _checkId(self, id, allow_dup=0):
    qid = _quote(id)
    nid = super(EntityManagerMixin, self)._checkId(qid, allow_dup)
    return nid or qid

  def _setObject(self, id, object, *args, **kw):
    # the id may be quoted or unquoted -- we ignore it altogether.
    id = object.id
    return super(EntityManagerMixin, self)._setObject(id, object, *args, **kw)


def initialize(context):
  from dm.zope.schema.z2.constructor import add_form_factory, SchemaConfiguredZmiAddForm
  
  context.registerClass(
    EntityByUrl,
    constructors=(add_form_factory(EntityByUrl, form_class=SchemaConfiguredZmiAddForm),),
    permission=manage_saml,
    interfaces=(IEntity,),
    visibility=None,
    )


### auxiliaries
def _quote(id):
  # this does not yet allow all entity ids but should support the sensible ones
  return quote(id, "").replace("%", "$")

def _unquote(id):
  return unquote(id.replace("$", "%"))

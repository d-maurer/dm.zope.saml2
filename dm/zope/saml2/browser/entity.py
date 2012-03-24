"""Entity presentation."""
from zope.interface import Interface
from zope.schema import Bool
from zope.formlib.form import Fields, action

from dm.zope.schema.z2.template import form_template
from dm.zope.schema.z2.form import ZmiMixin, PageForm

from dm.zope.saml2.interfaces import _

class IUpdateSchema(Interface):
  clear_existing_metadata = Bool(
    title=_(u"clear_existing_metadata", u"Clear existing metadata"),
    required=False,
    )

class Update(ZmiMixin, PageForm):
  label = _(u"entity_metadata_update", u"Metadata update")
  form_fields = Fields(IUpdateSchema)

  @action(_(u"update_metadata", u"Update metadata"))
  def update_(self, action, data):
    e = self.context
    e.aq_inner.aq_parent.metadata_by_id(e.id).fetch_metadata(data["clear_existing_metadata"])
    self.status = _(u"metadata_updated", u"Metadata updated")

  





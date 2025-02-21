# Copyright (C) 2011-2019 by Dr. Dieter Maurer <dieter@handshake.de>
"""SAML2 support."""

def initialize(context):
  from .authority import SamlAuthority, AuthorityAddForm
  from .permission import manage_saml
  from dm.zope.schema.z2.constructor import add_form_factory, SchemaConfiguredZmiAddForm

  context.registerClass(
    SamlAuthority,
    constructors=(add_form_factory(SamlAuthority, form_class=AuthorityAddForm),),
    permission=manage_saml,
    )

  from .idpsso.idpsso import initialize; initialize(context)
  from .spsso import initialize; initialize(context)
  from .entity import initialize; initialize(context)

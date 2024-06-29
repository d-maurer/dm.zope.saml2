# Copyright (C) 2011-2024 by Dr. Dieter Maurer <dieter.maurer@online.de>
"""Portial IDP tests.
"""
from copy import deepcopy
from unittest import TestCase

from .test_authority import LayerWithAuthority


class IdpTests(TestCase):
  layer = LayerWithAuthority

  def test_E87(self):
    auth = self.layer.auth
    idp = self.layer.idp
    select = idp._attribute_consuming_service
    md = deepcopy(auth.metadata_by_id("feid").get_recent_metadata())
    acss = md.SPSSODescriptor[0].AttributeConsumingService
    o_acs = acss[0]
    acs_2_false = deepcopy(o_acs); acs_2_false.isDefault = False; acs_2_false.index = 2
    # test index based access
    acss[:] = [o_acs, acs_2_false]
    self.assertIs(select(md, 2), acs_2_false)
    # test `isDefault`
    acss[:] = [acs_2_false, o_acs]
    self.assertIs(select(md), o_acs)
    # test first `isDeault not false`
    acs_1_none = deepcopy(o_acs); acs_1_none.isDefault = None
    acss[:] = [acs_2_false, acs_1_none]
    self.assertIs(select(md), acs_1_none)
    # test first
    acs_1_false = deepcopy(acs_2_false); acs_1_false.index = 1
    acss[:] = [acs_1_false, acs_2_false]
    self.assertIs(select(md), acs_1_false)


    


    

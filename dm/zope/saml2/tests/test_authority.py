# Copyright (C) 2011-2024 by Dr. Dieter Maurer <dieter.maurer@online.de>
"""Partial authority tests.
"""
from os.path import dirname, join
from datetime import timedelta
from unittest import TestCase

from transaction import abort
from ZODB.DemoStorage import DemoStorage
from ZODB.DB import DB

from zope.lifecycleevent.interfaces import IObjectModifiedEvent
from zope.lifecycleevent import ObjectModifiedEvent
from zope.event import notify
from zope.component import provideUtility, provideHandler
from zope.component.event import objectEventNotify
from zope.testing.cleanup import cleanUp
from OFS.Folder import Folder

from ..interfaces import ISamlAuthority
from ..authority import SamlAuthority, signature_context_changed, \
     EntityMetadata, OwnEntity, utcnow
from ..entity import EntityByUrl
from ..idpsso.idpsso import SimpleIdpssoAp


resdir = join(dirname(__file__), "resources")


class LayerWithZodbConnection:
  @classmethod
  def setUp(cls):
    cls.zodb = DB(DemoStorage())
    cls.conn = cls.zodb.open()
    cls.root = cls.conn.root()

  @classmethod
  def tearDown(cls):
    abort()
    cls.conn.close()
    cls.zodb.close()

    
class LayerWithFolder(LayerWithZodbConnection):
  @classmethod
  def setUp(cls):
    cls.folder = f = Folder("folder")
    cls.root.folder = f

  @classmethod
  def tearDown(cls):
    del cls.root.folder

  
class LayerWithAuthority(LayerWithFolder):
  @classmethod
  def setUp(cls):
    f = cls.folder
    auth = cls.authority = SamlAuthority()
    auth._setId("auth")
    auth.__init__(entity_id="eid",
                  certificate=join(resdir, "auth.cert"),
                  private_key=join(resdir, "auth.key"),
                  base_url="https://localhost")
    f._setObject(auth.id, auth)
    auth = cls.auth = f.auth
    provideUtility(auth, ISamlAuthority)
    auth.add_entity(OwnEntity())
    provideHandler(objectEventNotify)
    provideHandler(signature_context_changed,
                   adapts=(EntityMetadata, IObjectModifiedEvent))
    idp = SimpleIdpssoAp()
    idp._setId("idp")
    f._setObject(idp.getId(), idp)
    idp = f.idp
    auth.register_role_implementor(idp)
    cls.idp = idp
    e = EntityByUrl(url="file://" + resdir + "/feid.xml")
    e._setId("feid")
    auth._setObject(None, e)

  @classmethod
  def tearDown(cls):
    cls.folder._delOb("auth")
    cleanUp()


class KeysManagerTests(TestCase):
  layer = LayerWithAuthority

  def test_own_keys(self):
    auth = self.layer.auth
    mgr = auth._get_keys_manager()
    eid = auth.entity_id
    m = mgr.eid2volatile_info
    self.assertNotIn(eid, m)
    keys = mgr[eid]
    self.assertEqual(len(keys), 1)
    volatile = m[eid]
    self.assertEqual(volatile.get(), (None, keys))
    # invalidate the key
    auth._update()
    self.assertNotIn(eid, m)
    keys = mgr[eid]
    self.assertEqual(len(keys), 1)

  def test_foreign_keys(self):
    auth = self.layer.auth
    mgr = auth._get_keys_manager()
    eid = "feid"
    m = mgr.eid2volatile_info
    self.assertNotIn(eid, m)
    keys = mgr[eid]
    self.assertEqual(len(keys), 1)
    volatile = m[eid]
    validUntil, v_keys = volatile.get()
    self.assertIs(v_keys, keys)
    # invalidate
    notify(ObjectModifiedEvent(auth.metadata_by_id(eid)))
    self.assertNotIn(eid, m)
    keys = mgr[eid]
    self.assertEqual(len(keys), 1)
    # outdated info
    n_keys = mgr[eid]
    self.assertIs(n_keys, keys)
    volatile = m[eid]
    volatile.set((utcnow() - timedelta(days=1), keys)) # outdate
    n_keys = mgr[eid]
    self.assertIsNot(n_keys, keys)
    

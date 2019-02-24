# Copyright (C) 2019 by Dr. Dieter Maurer <dieter@handshake.de>
"""Integrate with `plone.protect`."""
from decorator import decorator

try: from plone.protect.utils import safeWrite
except ImportError: safeWrite = None

from BTrees.OOBTree import OOBTree

if safeWrite is None:
  # `plone.protect` not available
  def csrf_safe_write(obj): pass
  def csrf_safe(f): return f
  class CsrfAwareOOBTree(OOBTree): pass
else:
  # with `plone.protext`
  csrf_safe_write = safeWrite

  @decorator
  def csrf_safe(f, self, *args, **kw):
    """mark objects managed by `self._p_jar` (newly) modified by *f* as CSRF safe."""
    registered = getattr(getattr(self, "_p_jar", None),
                         "_registered_objects", []
                         )
    nr = len(registered)
    try: return f(self, *args, **kw)
    finally:
      for i in range(nr, len(registered)):  # newly registered
        safeWrite(registered[i])

  
  class CsrfAwareMapping(object):
    """Mixin class for CSRF aware mapping.

    Mapping subclasses with this mixin allow for modifications
    despite CSRF protection.

    Note: might need to decorate more BTree methods
    """
    @csrf_safe
    def __setitem__(self, key, value):
      return super(CsrfAwareMapping, self).__setitem__(key, value)

    @csrf_safe
    def __delitem__(self, key):
      return super(CsrfAwareMapping, self).__delitem__(key)

    @csrf_safe
    def clear(self):
      return super(CsrfAwareMapping, self).clear()

  class CsrfAwareOOBTree(CsrfAwareMapping, OOBTree): pass

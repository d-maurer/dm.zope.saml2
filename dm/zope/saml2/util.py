# Copyright (C) 2011-2012 by Dr. Dieter Maurer <dieter@handshake.de>
"""Utilities."""
from zope.interface import alsoProvides
from zope.component import getUtility
from persistent import Persistent

def datetime_rfc822(dt):
  """format *dt* as an rfc822 date in GMT."""
  # this should be easier!
  from time import mktime
  from email.Utils import formatdate
  
  return formatdate(mktime(dt.timetuple()), usegmt=True)


def vocab_from_urns(urns):
  """turn sequence *urns* into a vocabulary.

  Each *urn* defines a term and the last `:` separated component the title.
  """
  from zope.schema.vocabulary import SimpleVocabulary, SimpleTerm

  return SimpleVocabulary(tuple(SimpleTerm(urn, title=urn.split(":")[-1])
                                for urn in urns
                                ))


# should propably be moved into a general utility package as it
#  could be usefull in a variety of situations
class UtilityRelay(object):
  """General utility implementing an object by a utility."""
  def __init__(self, interface, name=''):
    self.__interface = interface
    self.__name = name
    alsoProvides(self, interface)

  def getattr(self, k):
    if k not in self.__interface: raise AttributeError(k)
    return getattr(getUtility(self.__interface, self.__name), k)


# should propably be moved into a general utility package as it
#  could be usefull in a variety of situations
class ZodbSynchronized(Persistent):
  """auxiliary container for `_v_` variables synchronized via the ZODB.

  Used to maintain `_v_` caches consistent across several ZODB
  connections (in the same instance or across a range of them).
  """
  def invalidate(self):
    self._p_activate() # work around bug in some ZODB versions
    self._p_changed=True # ensure caches in other ZODB connections are flushed
    for k in self.__dict__.keys():
      if k.startswith("_v_"): delattr(self, k)


# Implement a `getCharset` function, no longer provided
#  by `Products.PlonePAS.utils`
#  For details, read the section "Text handling" in `README.txt`.
from zope.interface import Interface
from zope.component import queryAdapter

from Products.CMFCore.utils import getToolByName

class ICharset(Interface):
  """Marker interface for an adapter returning the charset used by a Plone portal."""

def getCharset(context):
  portal = getToolByName(context, "portal_url").getPortalObject()
  return queryAdapter(portal, ICharset, default="utf-8")

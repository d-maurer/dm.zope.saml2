# Copyright (C) 2011-2024 by Dr. Dieter Maurer <dieter.maurer@online.de>
"""``formlib`` patchups.

``formlib`` integration is often incomplete.
Especially, it is not sufficiently complete for ``dm.zope.saml2``.
Extensions are necessary.

Unfortunately, other applications and components, too,
might require extensions and those may conflict with ours.
To facilitate handling od those caaes, our
``formlib`` extensions are registered in ``formlib.zcml``.
If they make problems, use the ZCML registrations from
``core.zcml`` rather than ``configure.zcml`` (this excludes
the ``formlib`` extensions) and coordinate 
which ``formlib`` extensions are used.
"""
from zope.interface import implementer
from zope.component import adapter
from zope.schema.interfaces import IVocabulary
from zope.publisher.interfaces.browser import IBrowserRequest
from zope.browser.interfaces import ITerms


@adapter(IVocabulary, IBrowserRequest)
@implementer(ITerms)
def vocab2terms(vocab, request): return vocab


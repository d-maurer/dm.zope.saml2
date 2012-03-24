# Copyright (C) 2011-2012 by Dr. Dieter Maurer <dieter@handshake.de>
"""SPSSO role.

The architecture for this role consists of the role itself and a
cooperating `PlonePAS` plugin. In the simplest (and usual) case,
both fall together.
However, for special purposes (several sites share a common service provider),
role and plugin can be separate objects where the role is used by
several plugins.

The role does not have a user interface of itself. It operates as a
purely internal service. Therefore, it can be instantiated outside of
a portal context. The role is responsible for all SAML2 handling.
It communicates with the plugin indirectly via cookies. Therefore,
role and plugin must share those cookies. The plugin treats those
cookies as opaque values and uses a role method to access its content.
As a consequence, authentication sessions and attribute values
are shared among plugins. It is impossible that the same user
has different identities or different attributes in sites using
the same SPSSO role.

User ids have the form *NameQualifier*::*Id*, where *NameQualifier*
identifies the authenticating entity and *Id* specifies the id assigned
by it for the user in our usage. This means, that some information
from the `NameID` used in SAML2 is lost.

The plugin implements the `IExtractionPlugin`,
`IAuthenticationPlugin`, `ICredentialResetPlugin` and `IChallengePlugin`.
If you use the standard Plone `ISessionPlugin`, some SAML2 features
(such as global logout, lifetime limitation of the authentication session)
may not work (as the session plugin continues to authenticate the user);
therefore, you may consider its deactivation.
If you want to allow local authentication beside SAML2 authentication,
you need your own challenge plugin whose login form support idp selection
and local login.

Sensible cookie values can optionaly be encrypted. In this case,
an `IEncryption` utility must be registered. This package contains
an example implementation based on the `mcrypt` extension, but
does not register it by default.
If not encrypted, sensible cookie values are signed
(and thereby protected against manipulation).

The role operates together with an SAML authority, accessed as
an `ISamlAuthority` utility. A corresponding registration must
be available in the context of each plugin and the role.
"""

def initialize(context):
  from spsso import initialize; initialize(context)
  from plugin import initialize; initialize(context)

# Copyright (C) 2011-2012 by Dr. Dieter Maurer <dieter@handshake.de>
"""Identity provider SSO.

We assume to live inside a (Plone) portal and can rely on its login
infrastructure (probably with an adapted login form).

We assume the existance of a local `ISAMLAuthority` utility. It may be inside
the portal itself but more likely it lives above the portal to be usable
by several portals.

For special services, such as `SingleLogout`, different
authentication strenght, limited authentication
session lifetime, correct authentication time, cookie authentication,
more portal infrastructure will need to be adapted
(especially, the `Session` plugin).
We plan to provide adequate base implementations in the future.
"""


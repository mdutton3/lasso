# -*- coding: UTF-8 -*-


# Lasso Simulator
# By: Emmanuel Raviart <eraviart@entrouvert.com>
#
# Copyright (C) 2004 Entr'ouvert
# http://lasso.entrouvert.org
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


import lasso

from IdentityProvider import IdentityProviderMixin
from ServiceProvider import ServiceProviderMixin


class LibertyEnabledProxyMixin(IdentityProviderMixin, ServiceProviderMixin):
    def __init__(self):
        ServiceProviderMixin.__init__(self)
        IdentityProviderMixin.__init__(self)

    def login(self, handler):
        # Before, this proxy was considered as an identity provider. Now it is a service provider.
        return ServiceProviderMixin.login(self, handler)

    def login_failed(self, handler):
        # Before, this proxy was considered as a service provider. Now it acts again as a service
        # provider.
        return self.login_done(handler, False, None)

    def assertionConsumer_done(self, handler):
        # Before, this proxy was considered as a service provider. Now it acts again as a service
        # provider.
        # FIXME: We should retrieve authentication method from session.lassoSessionDump.
        return self.login_done(handler, True, lasso.samlAuthenticationMethodPassword)

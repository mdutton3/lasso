# -*- coding: UTF-8 -*-


# Python Lasso Simulator
#
# Copyright (C) 2004 Entr'ouvert
# http://lasso.entrouvert.org
# 
# Author: Emmanuel Raviart <eraviart@entrouvert.com>
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

from websimulator import *


class Provider(WebSite):
    responseHeaders = WebSite.responseHeaders.copy()
    responseHeaders.update({
        'Liberty-Enabled': 'LIBV=urn:liberty:iff:2003-08,http://projectliberty.org/specs/v1',
        })
    serverDump = None
    webUserIdsByNameIdentifier = None
    webSessionIdsByNameIdentifier = None

    def getServer(self):
        return lasso.Server.new_from_dump(self.serverDump)

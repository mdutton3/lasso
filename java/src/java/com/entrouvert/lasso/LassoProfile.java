/*
 * JLasso -- Java bindings for Lasso library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: Benjamin Poussin <poussin@codelutin.com>
 *          Emmanuel Raviart <eraviart@entrouvert.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package com.entrouvert.lasso;

public abstract class LassoProfile extends LassoObject { // LassoProfile
    protected LassoIdentity identity = null;
    protected LassoNode request = null;
    protected LassoNode response = null;
    protected LassoServer server = null;
    protected LassoSession session = null;

    native protected void getCIdentity();

    native protected void getCRequest();

    native protected void getCResponse();

    native protected void getCServer();

    native protected void getCSession();

    native protected int setCIdentity();

    native protected int setCSession();

    public LassoIdentity getIdentity() {
        getCIdentity();
        return identity;
    }

    native public String getMsgBody();

    native public String getMsgRelayState();

    native public String getNameIdentifier();

    native public String getMsgUrl();

    native public String getProviderID();

    public LassoNode getRequest() {
        getCRequest();
        return request;
    }

    native public int getRequestType();

    public LassoNode getResponse() {
        getCResponse();
        return response;
    }

    native public int gettResponseType();

    public LassoServer getServer() {
        getCServer();
        return server;
    }

    public LassoSession getSession() {
        getCSession();
        return session;
    }

    public int setIdentity(LassoIdentity identity) {
        this.identity = identity;
	return setCIdentity();
    }

    native public int setIdentityFromDump(String identityDump);

    public int setSession(LassoSession session) {
        this.session = session;
	return setCSession();
    }

    native public int setSessionFromDump(String sessionDump);

} // LassoProfile

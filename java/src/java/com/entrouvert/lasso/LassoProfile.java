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
    protected LassoNode request = null;
    protected LassoNode response = null;
    protected LassoServer server = null;
    protected LassoUser user = null;

    native protected void initRequestField();

    native protected void initResponseField();

    native protected void initServerField();

    native protected void initUserField();

    native public String getMsgBody();

    native public String getMsgRelayState();

    native public String getNameIdentifier();

    native public String getMsgUrl();

    native public String getProviderID();

    public LassoNode getRequest(){
        initRequestField();
        return request;
    }

    native public int getRequestType();

    public LassoNode getResponse(){
        initResponseField();
        return response;
    }

    native public int gettResponseType();

    public LassoServer getServer(){
        initServerField();
        return server;
    }

    public LassoUser getUser(){
        initUserField();
        return user;
    }

    native public int setUserFromDump(String userDump);

} // LassoProfile

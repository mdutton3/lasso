/* $Id$
 *
 * JLasso -- Java bindings for Lasso library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.labs.libre-entreprise.org
 *
 * Authors: Benjamin Poussin <poussin@codelutin.com>
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

/* *
 * LassoLogin.java
 *
 * Created: 16 juil. 2004
 *
 * @author Benjamin Poussin <poussin@codelutin.com>
 * @version $Revision$
 *
 * Mise a jour: $Date$
 * par : $Author$
 */

package com.entrouvert.lasso;

public class LassoLogin extends LassoProfileContext { // LassoLogin

    public LassoLogin(LassoServer server, LassoUser user){
        this.server = server;
        this.user = user;
        init(server, user);
    }

    public LassoLogin(LassoServer server, LassoUser user, String dump){
        this.server = server;
        this.user = user;
        initFromDump(server, user, dump);
    }

    native protected void init(LassoServer server, LassoUser user);

    native protected void initFromDump(LassoServer server,
                                       LassoUser user,
                                       String dump);

    native public int buildArtifactMsg(int authenticationResult,
                                       String authenticationMethod,
                                       String reauthenticateOnOrAfter,
                                       int method);

    native public int buildAuthnRequestMsg();

    native public int buildAuthnResponseMsg(int authenticationResult,
                                            String authenticationMethod,
                                            String reauthenticateOnOrAfter);

    native public int buildRequestMsg();

    native public String dump();

    native public int initAuthnRequest(String providerId);

    native public int initFromAuthnRequestMsg(String authnRequestMsg,
                                              int authnRequestMethod);

    native public int initRequest(String responseMsg,
                                  int responseMethod);

    native public int mustAuthenticate();

    native public int processAuthnResponseMsg(String authnResponseMsg);

    native public int processRequestMsg(String requestMsg);

    native public int processResponseMsg(String responseMsg);

} // LassoLogin


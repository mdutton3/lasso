/*
 * ColdFusionLasso -- ColdFusion bindings for Lasso library
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: See AUTHORS file in top-level directory.
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


import com.entrouvert.lasso.Identity;
import com.entrouvert.lasso.lassoConstants;
import com.entrouvert.lasso.lasso;
import com.entrouvert.lasso.Logout;
import com.entrouvert.lasso.SamlNameIdentifier;
import com.entrouvert.lasso.Server;
import com.entrouvert.lasso.Session;


public class CFLassoSingleLogout {
    /* A simple service provider single logout */

    protected Logout logout = null;
    protected Server server = null;

    public String idpProviderId = null;

    public void buildRequestMsg() {
	logout.buildRequestMsg();
    }

    public void configure(String metadataPath, String privateKeyPath, String idpProviderId,
			  String idpMetadataPath, String idpPublicKeyPath) {
        server = new Server(metadataPath, privateKeyPath, null, null);
	this.idpProviderId = idpProviderId;
        server.addProvider(lasso.PROVIDER_ROLE_IDP, idpMetadataPath, idpPublicKeyPath, null);
        logout = new Logout(server);
    }

    public String getIdentityDump() {
	Identity identity = logout.getIdentity();
	if (identity != null)
	    return identity.dump();
	else
	    return null;
    }

    public String getMsgBody() {
	return logout.getMsgBody();
    }

    public String getMsgUrl() {
	return logout.getMsgUrl();
    }

    public String getNameIdentifier() {
	SamlNameIdentifier nameIdentifier = logout.getNameIdentifier();
	if (nameIdentifier == null)
	    return null;
	else
	    return nameIdentifier.getContent();
    }

    public String getSessionDump() {
	Session session = logout.getSession();
	if (session != null)
	    return session.dump();
	else
	    return null;
    }

    public void initRequest() {
	logout.initRequest(idpProviderId, lassoConstants.HTTP_METHOD_ANY);
    }

    public void processResponseMsg(String responseMsg) {
	logout.processResponseMsg(responseMsg);
    }

    public void setIdentityFromDump(String identityDump) {
	logout.setIdentityFromDump(identityDump);
    }

    public void setSessionFromDump(String sessionDump) {
	logout.setSessionFromDump(sessionDump);
    }
}

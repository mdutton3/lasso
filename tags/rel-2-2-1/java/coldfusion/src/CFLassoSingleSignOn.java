/*
 * ColdFusionLasso -- ColdFusion bindings for Lasso library
 *
 * Copyright (C) 2004-2007 Entr'ouvert
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


/*
 * Simple wrapper for JLasso, to ease its use by ColdFusion applications.
 *
 * To compile it:
 * $ javac -classpath ../../lasso.jar *.java
 *
 * To test it:
 * $ export LD_LIBRARY_PATH=../../.libs/
 * $ java -classpath ../../lasso.jar:. CFLassoSingleSignOn

 *
 * To use it:
 * $ jar cf CFLasso.jar *.class
 * edit ColdFusion file bin/jvm.config:
 *   - Add libjlasso.so directory to java.library.path variable.
 *   - Add lasso.jar & CFLasso.jar to java.class.path variable.
 */

import com.entrouvert.lasso.LibAuthnRequest;
import com.entrouvert.lasso.Identity;
import com.entrouvert.lasso.lassoConstants;
import com.entrouvert.lasso.lasso;
import com.entrouvert.lasso.Login;
import com.entrouvert.lasso.SamlNameIdentifier;
import com.entrouvert.lasso.Server;
import com.entrouvert.lasso.Session;


public class CFLassoSingleSignOn {
    /* A simple service provider single sign-on */

    protected Login login = null;
    protected Server server = null;

    public String idpProviderId = null;

    public void acceptSso() {
	login.acceptSso();
    }

    public void buildAuthnRequestMsg() {
        login.buildAuthnRequestMsg();
    }

    public void buildRequestMsg() {
	login.buildRequestMsg();
    }

    public void configure(String metadataPath, String privateKeyPath, String idpProviderId,
			  String idpMetadataPath, String idpPublicKeyPath) {
        server = new Server(metadataPath, privateKeyPath, null, null);
	this.idpProviderId = idpProviderId;
        server.addProvider(lasso.PROVIDER_ROLE_IDP, idpMetadataPath, idpPublicKeyPath, null);
        login = new Login(server);
    }

    public String getIdentityDump() {
	Identity identity = login.getIdentity();
	if (identity != null)
	    return identity.dump();
	else
	    return null;
    }

    public String getMsgBody() {
	return login.getMsgBody();
    }

    public String getMsgRelayState() {
	return login.getMsgRelayState();
    }

    public String getMsgUrl() {
	return login.getMsgUrl();
    }

    public String getNameIdentifier() {
	SamlNameIdentifier nameIdentifier = login.getNameIdentifier();
	if (nameIdentifier == null)
	    return null;
	else
	    return nameIdentifier.getContent();
    }

    public String getSessionDump() {
	Session session = login.getSession();
	if (session != null)
	    return session.dump();
	else
	    return null;
    }

    public void initAuthnRequest(String relayState) {
	LibAuthnRequest authnRequest;
	String authnRequestUrl;

        login.initAuthnRequest(idpProviderId, lassoConstants.HTTP_METHOD_REDIRECT);
	authnRequest = (LibAuthnRequest) login.getRequest();
        authnRequest.setIsPassive(false);
        authnRequest.setNameIdPolicy(lassoConstants.LIB_NAMEID_POLICY_TYPE_FEDERATED);
        authnRequest.setConsent(lassoConstants.LIB_CONSENT_OBTAINED);
	if (relayState != null)
	    authnRequest.setRelayState(relayState);
    }

    public void initRequest(String queryString) {
	login.initRequest(queryString, lassoConstants.HTTP_METHOD_REDIRECT);
    }

    static public void main(String [] args) {
	CFLassoSingleSignOn lasso = new CFLassoSingleSignOn();
	lasso.configure("../../../tests/data/sp2-la/metadata.xml",
			"../../../tests/data/sp2-la/private-key-raw.pem",
			"https://idp2/metadata",
			"../../../tests/data/idp2-la/metadata.xml",
			"../../../tests/data/idp2-la/public-key.pem");
	lasso.initAuthnRequest("data-to-get-back");
	lasso.buildAuthnRequestMsg();
	String ssoUrl = lasso.getMsgUrl();
	System.out.println("Test");
	System.out.print("Identity provider single sign-on URL = ");
	System.out.println(ssoUrl);
    }

    public void processResponseMsg(String responseMsg) {
	login.processResponseMsg(responseMsg);
    }

    public void setIdentityFromDump(String identityDump) {
	login.setIdentityFromDump(identityDump);
    }

    public void setSessionFromDump(String sessionDump) {
	login.setSessionFromDump(sessionDump);
    }
}

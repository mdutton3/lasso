/*
 * ColdFusionLasso -- ColdFusion bindings for Lasso library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: Emmanuel Raviart <eraviart@entrouvert.com>
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
 * $ javac -classpath ../../lasso.jar CFLasso.java
 *
 * To test it:
 * $ export LD_LIBRARY_PATH=../../.libs/
 * $ java -classpath ../../lasso.jar:. CFLasso
 *
 * To use it:
 * $ jar cf CFLasso.jar CFLasso.class
 * edit ColdFusion file bin/jvm.config:
 *   - Add libjlasso.so directory to java.library.path variable.
 *   - Add lasso.jar & CFLasso.jar to java.class.path variable.
 */

import com.entrouvert.lasso.AuthnRequest;
import com.entrouvert.lasso.lassoConstants;
import com.entrouvert.lasso.lasso;
import com.entrouvert.lasso.Login;
import com.entrouvert.lasso.Server;


public class CFLasso {
    /* A simple service provider */

    protected Server server = null;

    public String idpProviderId = null;

    public void configure(String metadataPath, String publicKeyPath, String privateKeyPath,
			  String idpProviderId, String idpMetadataPath, String idpPublicKeyPath) {
        server = new Server(metadataPath, publicKeyPath, privateKeyPath, null,
			    lassoConstants.signatureMethodRsaSha1);
	this.idpProviderId = idpProviderId;
        server.addProvider(idpMetadataPath, idpPublicKeyPath, null);
    }

    public String login(String relayState) {
	AuthnRequest authnRequest;
	Login login;
	String authnRequestUrl;

        login = new Login(server);
        login.initAuthnRequest(lassoConstants.httpMethodRedirect);
	authnRequest = login.getAuthnRequest();
        authnRequest.setIsPassive(false);
        authnRequest.setNameIdPolicy(lassoConstants.libNameIdPolicyTypeFederated);
        authnRequest.setConsent(lassoConstants.libConsentObtained);
	if (relayState != null)
	    authnRequest.setRelayState(relayState);
        login.buildAuthnRequestMsg(idpProviderId);
        authnRequestUrl = login.getMsgUrl();
	return authnRequestUrl;
    }

    static public void main(String [] args) {
	CFLasso lasso = new CFLasso();
	lasso.configure("../../../tests/data/sp2-la/metadata.xml",
			"../../../tests/data/sp2-la/public-key.pem",
			"../../../tests/data/sp2-la/private-key-raw.pem",
			"https://idp2/metadata",
			"../../../tests/data/idp2-la/metadata.xml",
			"../../../tests/data/idp2-la/public-key.pem");
	String ssoUrl = lasso.login("data to get back");
	System.out.println("Test");
	System.out.print("Identity provider single sign-on URL = ");
	System.out.println(ssoUrl);
    }
}

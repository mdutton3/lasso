/* 
 * install lasso then compile with
 *  mcs -g -nologo -pkg:lasso-sharp -out:perfs.exe perfs.cs 
 */

using System;

public class perfs
{
    static void Main() 
    {
	lasso.lasso.init();

	lasso.Server server = new lasso.Server(
			"../../tests/data/sp1-la/metadata.xml",
			"../../tests/data/sp1-la/private-key-raw.pem",
			null,
			"../../tests/data/sp1-la/certificate.pem");

	server.addProvider(lasso.LassoProviderRole.providerRoleSp,
			"../../tests/data/idp1-la/metadata.xml",
			"../../tests/data/idp1-la/public-key.pem",
			"../../tests/data/ca1-la/certificate.pem");

	lasso.Login login = new lasso.Login(server);
	
	login.initAuthnRequest("https://idp1/metadata", (lasso.LassoHttpMethod)4);
	lasso.LibAuthnRequest request = (lasso.LibAuthnRequest)login.request;
	login.request.protocolProfile = lasso.lasso.libProtocolProfileBrwsPost;
	login.buildAuthnRequestMsg();

	Console.WriteLine(login.msgUrl);

	lasso.lasso.shutdown();
    }
}

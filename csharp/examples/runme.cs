/* 
 * install lasso then compile with
 *  mcs -g -nologo -pkg:lasso-sharp -out:runme.exe runme.cs 
 */

using System;

public class runme
{
    static void Main() 
    {
	lasso.lasso.init();

	lasso.Server server = new lasso.Server(
			"../../tests/data/sp1-la/metadata.xml",
			"../../tests/data/sp1-la/private-key-raw.pem",
			null,
			"../../tests/data/sp1-la/certificate.pem");
	server.addProvider(lasso.LassoProviderRole.PROVIDER_ROLE_SP,
			"../../tests/data/idp1-la/metadata.xml",
			"../../tests/data/idp1-la/public-key.pem",
			"../../tests/data/ca1-la/certificate.pem");
	Console.WriteLine(server.dump());

        lasso.lasso.shutdown();
    }
}

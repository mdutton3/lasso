/* 
 * install lasso then compile with
 *  mcs -g -nologo -pkg:lasso-sharp -out:runme.exe runme.cs 
 */

using System;

public class runme
{
    static void Main() 
    {
        Console.WriteLine("lasso_init");
	lasso.lasso_init();

	Console.WriteLine("new LassoServer");
	LassoServer server = new LassoServer(
			"../tests/data/idp1-la/metadata.xml",
			"",
			"../tests/data/idp1-la/private-key-raw.pem",
			"../tests/data/idp1-la/certificate.pem",
			lasso.lassoSignatureMethodRsaSha1);


        Console.WriteLine("lasso_shutdown");
        lasso.lasso_shutdown();
    }
}

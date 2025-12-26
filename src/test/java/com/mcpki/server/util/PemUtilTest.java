/*************************************************************************
*																		 *
* https://mcpki.org														 *
* 																		 *
* Copyright (C) 2025 A. Jakobs										 	 *
* 																		 *
* This program is free software: you can redistribute it and/or modify	 *
* it under the terms of the GNU General Public License as published by	 *
* the Free Software Foundation, either version 3 of the License, or		 *
* (at your option) any later version.									 *
* 																		 *
* This program is distributed in the hope that it will be useful,		 *
* but WITHOUT ANY WARRANTY; without even the implied warranty of		 *
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the			 *
* GNU General Public License for more details.							 *
* 																		 *
* You should have received a copy of the GNU General Public License		 *
* along with this program. If not, see <http://www.gnu.org/licenses/>.	 *
* 																		 *
*************************************************************************/

package com.mcpki.server.util;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class PemUtilTest {

	// @formatter:off
	private static final String base64Certificate = "MIICjzCCAXegAwIBAgIUavq5hQjs2KUowhszOkZqX4dW23YwDQYJKoZIhvcNAQELBQAwLzEZMBcGA1UEAwwQbWNwa2ktcnNhLXN1Yi1jYTESMBAGA1UECgwJbWNwa2kub3JnMB4XDTI1MDczMTE3MTExNFoXDTI1MDgzMDE3MTExM1owJTEPMA0GA1UEAwwGQW5kcmVzMRIwEAYDVQQKDAltY3BraS5vcmcwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAxjOFSN/k36qg18YyKew/N4Ceo9F4ily8N9npijGSqF7YwPDww7NeMBhheT+nvkwN3qLJ68CpipqHDEZxUN9iVQIDAQABo3UwczAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFBT6STI4sI4N+oq5KDucX+PfVisTMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQWBBSJY52M1GQS3R5JNqtGhwuw9eFW1jAOBgNVHQ8BAf8EBAMCBeAwDQYJKoZIhvcNAQELBQADggEBACsE8PnQqZrv90TZhDFzkJ2LFFsu2yaV5g8/xix+iVf9bokEMtzhp5rIiRQqhM+Sj6v1IY4JoKPJt3qQ0e3q9T3q3soUYtObe2Gd+l9WcQDKhqVTNHAQ7JybUeNZXFjaLpcaTT3lXtDOqupxPwGMjUR4+66jjr6WCdPe7KZ/kfUWWz7OKC5sMya4CvCZunwkYF70KbkJKKs2Vozwo9di22YG279u8clCIns/O1BprIPNUx/pqO6bUQcNBkOyi3U/uPW7KAUj98q3siC90gCMDhgVkwveyo/DZYdjvvVJei4UbbN0/+JWrObPO0XNYLfFnhY1AB/Wc7Febm78+zNRznk=";

	private static final String pemCertificate = 
		"-----BEGIN CERTIFICATE-----\n"
		+ "MIICjzCCAXegAwIBAgIUavq5hQjs2KUowhszOkZqX4dW23YwDQYJKoZIhvcNAQEL\n"
		+ "BQAwLzEZMBcGA1UEAwwQbWNwa2ktcnNhLXN1Yi1jYTESMBAGA1UECgwJbWNwa2ku\n"
		+ "b3JnMB4XDTI1MDczMTE3MTExNFoXDTI1MDgzMDE3MTExM1owJTEPMA0GA1UEAwwG\n"
		+ "QW5kcmVzMRIwEAYDVQQKDAltY3BraS5vcmcwXDANBgkqhkiG9w0BAQEFAANLADBI\n"
		+ "AkEAxjOFSN/k36qg18YyKew/N4Ceo9F4ily8N9npijGSqF7YwPDww7NeMBhheT+n\n"
		+ "vkwN3qLJ68CpipqHDEZxUN9iVQIDAQABo3UwczAMBgNVHRMBAf8EAjAAMB8GA1Ud\n"
		+ "IwQYMBaAFBT6STI4sI4N+oq5KDucX+PfVisTMBMGA1UdJQQMMAoGCCsGAQUFBwMB\n"
		+ "MB0GA1UdDgQWBBSJY52M1GQS3R5JNqtGhwuw9eFW1jAOBgNVHQ8BAf8EBAMCBeAw\n"
		+ "DQYJKoZIhvcNAQELBQADggEBACsE8PnQqZrv90TZhDFzkJ2LFFsu2yaV5g8/xix+\n"
		+ "iVf9bokEMtzhp5rIiRQqhM+Sj6v1IY4JoKPJt3qQ0e3q9T3q3soUYtObe2Gd+l9W\n"
		+ "cQDKhqVTNHAQ7JybUeNZXFjaLpcaTT3lXtDOqupxPwGMjUR4+66jjr6WCdPe7KZ/\n"
		+ "kfUWWz7OKC5sMya4CvCZunwkYF70KbkJKKs2Vozwo9di22YG279u8clCIns/O1Bp\n"
		+ "rIPNUx/pqO6bUQcNBkOyi3U/uPW7KAUj98q3siC90gCMDhgVkwveyo/DZYdjvvVJ\n"
		+ "ei4UbbN0/+JWrObPO0XNYLfFnhY1AB/Wc7Febm78+zNRznk=\n"
		+ "-----END CERTIFICATE-----";
	
	private static final String base64Crl = "MIIBKDCBkgIBATANBgkqhkiG9w0BAQsFADAvMRkwFwYDVQQDDBBtY3BraS1yc2Etc3ViLWNhMRIwEAYDVQQKDAltY3BraS5vcmcXDTI1MDgwMTEzMTk1NVoXDTI2MDEyODEzMTk1NFqgLzAtMB8GA1UdIwQYMBaAFPpaPtXjG5JH7LXC8tkv/OD5ZmZaMAoGA1UdFAQDAgEaMA0GCSqGSIb3DQEBCwUAA4GBAKN5sjOPaMSqLU51GHhRtS7/nnKPZQg85gpnNmNtpL1Azh3qp8aqG1tt99AXepaB9NQ8zakOLJLxdxkM3nvRWHyPQscyK1Ze5H3dFxZuw/HHDEp30cvAmsgqkbUOP8QorCerOh+GNMt193OizY3zo5NtBu1849L28ZbB+m6jxe0C";
	
	private static final String pemCrl=
		"-----BEGIN X509 CRL-----\n"
		+ "MIIBKDCBkgIBATANBgkqhkiG9w0BAQsFADAvMRkwFwYDVQQDDBBtY3BraS1yc2Et\n"
		+ "c3ViLWNhMRIwEAYDVQQKDAltY3BraS5vcmcXDTI1MDgwMTEzMTk1NVoXDTI2MDEy\n"
		+ "ODEzMTk1NFqgLzAtMB8GA1UdIwQYMBaAFPpaPtXjG5JH7LXC8tkv/OD5ZmZaMAoG\n"
		+ "A1UdFAQDAgEaMA0GCSqGSIb3DQEBCwUAA4GBAKN5sjOPaMSqLU51GHhRtS7/nnKP\n"
		+ "ZQg85gpnNmNtpL1Azh3qp8aqG1tt99AXepaB9NQ8zakOLJLxdxkM3nvRWHyPQscy\n"
		+ "K1Ze5H3dFxZuw/HHDEp30cvAmsgqkbUOP8QorCerOh+GNMt193OizY3zo5NtBu18\n"
		+ "49L28ZbB+m6jxe0C\n"
		+ "-----END X509 CRL-----";

	// @formatter:on
	
	@Test
	public void testToPemCertificate() {
		assertEquals(pemCertificate, PemUtil.toPemCertificate(base64Certificate), "Certificate does not match.");
	}
	
	@Test
	public void testToPemCrl() {
		assertEquals(pemCrl, PemUtil.toPemCrl(base64Crl), "CRL does not match.");
	}
}

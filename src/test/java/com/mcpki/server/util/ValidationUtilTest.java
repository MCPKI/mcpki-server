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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@SpringBootConfiguration
public class ValidationUtilTest {

	// @formatter:off
	
	private static final String csrExample1Org =
	      "-----BEGIN CERTIFICATE REQUEST-----\\n"
		+ "MIICsTCCAZkCAQAwQjEVMBMGA1UEAwwMZXhhbXBsZTEub3JnMQswCQYDVQQGEwJE\\n"
		+ "RTEMMAoGA1UECwwDREVWMQ4wDAYDVQQKDAVFSkJDQTCCASIwDQYJKoZIhvcNAQEB\\n"
		+ "BQADggEPADCCAQoCggEBAJXV2s5xgjM1VkVycoZi+oUhqzj8fmfDu9JUy8rFr9Ra\\n"
		+ "Uv9D2G9Ehp+pvxaAbt0444Zutv2h8kwpMp4jsDx2Wtf06rq6/7UpYY9YXGRyv0Lh\\n"
		+ "Ek0xQDogeXIhAKBK4xbVVciBs6YGLQGt/qK7UyWimoA1mDNbk3MTIb0yL2QsVdWo\\n"
		+ "d/aR2+X6AATNVNxJxnDksZYxXGZupt+I+HHHspLKDOuZpuegbPXm45E7tJ9EfRNF\\n"
		+ "Grg8b33oDCPXvK4zXj/EbSmP7entuMINnnTQpUxSa/BuQNs2bVqgZ4v980N/dm5K\\n"
		+ "0hO2DChTCX1qMgsmsHaeR/OVPrTLX4PkCsO0tnE4E8UCAwEAAaAqMCgGCSqGSIb3\\n"
		+ "DQEJDjEbMBkwFwYDVR0RBBAwDoIMZXhhbXBsZTEub3JnMA0GCSqGSIb3DQEBCwUA\\n"
		+ "A4IBAQBV+uhyY/oSKJl15I28Jp0B6i9D9dYyyqZkh+E1/RpA1ifA8WLGLKLgo9W8\\n"
		+ "De2wbqGC6Xq5kxCPIACXRsRJCev3fZZ2pU3ClTPY6V2MFdLJXxCTI2VJ2WKFquzF\\n"
		+ "kRASdHHpQ48gw0k+pwCdhb39hNFzPZ+asgiCwVBkUTORTNaPnrRRuA2AckcD3hUY\\n"
		+ "BV+EMt/P6kyfYbubVdFAL2lRFcRKzJP0tviXlJ+152GQR/CUisPpCOPcbG/H+O4m\\n"
		+ "nIqSYo4TwacKe7uA/jSQS7eIpQGRRzxK33TFf127wMRK9jxZqd24FVB3L9Gb8gUw\\n"
		+ "h+Xx/L8OWH359WcavlCCKl9t92pW\\n"
		+ "-----END CERTIFICATE REQUEST-----";
	
	private static final String p256SubCa =
		"-----BEGIN CERTIFICATE-----\\n"
		+ "MIIBzzCCAXSgAwIBAgIUNC7R0e0m9L5ogZPueUcGQc6vAF4wCgYIKoZIzj0EAwIw\\n"
		+ "NTEfMB0GA1UEAwwWbWNwa2ktcHJpbWUyNTYtcm9vdC1jYTESMBAGA1UECgwJbWNw\\n"
		+ "a2kub3JnMB4XDTI1MDcwMTEzMDgyMFoXDTI4MDYzMDEzMDgxOVowNDEeMBwGA1UE\\n"
		+ "AwwVbWNwa2ktcHJpbWUyNTYtc3ViLWNhMRIwEAYDVQQKDAltY3BraS5vcmcwWTAT\\n"
		+ "BgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ9PSThca5PcTcsZslBevskfn6MBHLw0yF/\\n"
		+ "BwiUAkysli4laqZ3wnaol78HmhuWhRKbL1i7qbrbZjD7mwgItGp8o2MwYTAPBgNV\\n"
		+ "HRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFOEDtZ9/F/r8r42puuYPn4+X3UMnMB0G\\n"
		+ "A1UdDgQWBBTPbVAbHKRTYVEnzQ4zVIhqxKB+AzAOBgNVHQ8BAf8EBAMCAYYwCgYI\\n"
		+ "KoZIzj0EAwIDSQAwRgIhAMFSa6+tTbnvKCieTQAPUDEIrMLY4wAgOGkMrABHLNh7\\n"
		+ "AiEAsINW1bqy30SCfQNvO/RYJ/DB+5zIhEJO6cFVTCkDGDU=\\n"
		+ "-----END CERTIFICATE-----";
		
	// @formatter:on

	private static final String dn = "CN=mcpki-rsa-sub-ca,O=mcpki.org";

	@Value("${com.mcpki.server.pem.length.min}")
	private int pemMinStrength;

	@Value("${com.mcpki.server.pem.length.max}")
	private int pemMaxStrength;
	
	@Value("${com.mcpki.server.dn.length.min}")
	private int dnMinLength;
	
	@Value("${com.mcpki.server.dn.length.max}")
	private int dnMaxLength;

	@Test
	public void testIsValidateCsr()
	{
		assertEquals(true, ValidationUtil.isValidPem(csrExample1Org, pemMinStrength, pemMaxStrength), "CSR is invalid PEM format.");
	}

	@Test
	public void testIsValidateCertificate()
	{
		assertEquals(true, ValidationUtil.isValidPemFormat(p256SubCa), "CA certificate is invalid PEM format.");
	}

	@Test
	public void testIsValidateDn()
	{
		assertEquals(true, ValidationUtil.isValidDn(dn, dnMinLength, dnMaxLength), "DN is invalid.");
	}

}

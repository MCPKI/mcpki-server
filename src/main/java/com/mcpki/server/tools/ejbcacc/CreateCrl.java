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

package com.mcpki.server.tools.ejbcacc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.mcpki.server.util.ValidationUtil;

/**
 * MCP tool to create a Certificate Revocation List (CRL) by an issuer.
 */
@Service
public class CreateCrl {

	private static final Logger log = LoggerFactory.getLogger(CreateCrl.class);

	@Value("${com.mcpki.server.tools.ejbca.rest.url}")
	private String baseUrl;

	@Value("${com.mcpki.server.dn.length.min}")
	private int dnMinLength;

	@Value("${com.mcpki.server.dn.length.max}")
	private int dnMaxLength;

	@Autowired
	@Qualifier("tls")
	public RestTemplate restTemplate;

	/**
	 * Issues a Certificate Revocation List (CRL) for the given issuer DN.
	 * 
	 * @param issuer_dn the issuer DN.
	 * @return the CreateCrlResponse object.
	 */
	@Tool(name = "create_crl", description = "Create CRL.")
	public CreateCrlResponse ejbca_createCrl(
			@ToolParam(description = "The subject DN of the issuing CA.") final String issuer_dn)
	{
		ValidationUtil.assertValidIssuerDn(issuer_dn, dnMinLength, dnMaxLength);

		final String url = baseUrl + "/v1/ca/" + issuer_dn + "/createcrl?deltacrl=false";
		if (log.isDebugEnabled()) {
			log.debug("Requested URL: " + url);
		}

		final HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		final HttpEntity<String> request = new HttpEntity<String>("{}", headers);
		final CreateCrlResponse response = restTemplate.postForObject(url, request, CreateCrlResponse.class);
		return response;
	}

	// @formatter:off
	/**
	 * {
	 *   "issuer_dn": 					"CN=mcpki-dilithium2-root-ca,O=mcpki.org",
	 *   "latest_crl_version": 			4,
	 *   "all_success": 				true
	 *   "error_code": 					400,
  	 *   "error_message": 				"CA with DN: CN=mcpki-dilithium2-root-ca does not exist."
	 */
	// @formatter:on
	record CreateCrlResponse(String issuer_dn, int latest_crl_version, boolean all_success, String error_code,
			String error_message) {
	}
}

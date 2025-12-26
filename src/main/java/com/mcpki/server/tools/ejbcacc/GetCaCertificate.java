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

import org.apache.tomcat.util.json.JSONParser;
import org.apache.tomcat.util.json.ParseException;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import com.mcpki.server.util.McpUtil;
import com.mcpki.server.util.ValidationUtil;

/**
 * MCP tool the get a CA certificate (chain).
 */
@Service
public class GetCaCertificate {

	private static final Logger log = LoggerFactory.getLogger(GetCaCertificate.class);

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
	 * Returns the PEM formatted CA certificate chain (last is root CA) including
	 * boundaries and Subject / Issuer annotation.
	 * 
	 * @param subject_dn the subject DN of the issuing CA.
	 * @return the CA certificate chain.
	 */
	@Tool(name = "get_ca_certificate", description = "Get CA certificate.")
	public GetCaCertificateResponse ejbca_getCaCertificate(
			@ToolParam(description = "The subject DN of the CA certificate.") String subject_dn)
	{
		ValidationUtil.assertValidIssuerDn(subject_dn, dnMinLength, dnMaxLength);

		final String url = baseUrl + "/v1/ca/" + subject_dn + "/certificate/download";
		if (log.isDebugEnabled()) {
			log.debug("Requested URL: " + url);
		}

		String payload;
		try {
			payload = restTemplate.getForObject(url, String.class);
			if (log.isDebugEnabled()) {
				log.debug("Got CA certificate chain for {}: {}: ", subject_dn, payload);
			}
		} catch (RestClientException e) {
			// Connection refused and others land here, so sanitize response.
			return new GetCaCertificateResponse(McpUtil.sanitizeResponse(e.getMessage(), baseUrl), null, null);
		}

		// If the string can be parsed as JSON string, it should be an error, otherwise
		// it is a string of the PEM encoded CA chain or a connection error.
		try {
			final JSONObject error = (JSONObject) new JSONParser(payload).parse();
			log.warn("Error: " + error.toJSONString());
			return new GetCaCertificateResponse(null, "400", "CA certificate chain was found.");
		} catch (ParseException e) {
			return new GetCaCertificateResponse(payload, null, null);
		}
	}

	// @formatter:off
	/**
	 * Type String including the CA chain in PEM format and annotation.
	 * 
	 * "Subject: CN=mcpki-dilithium2-root-ca,O=mcpki.org\nIssuer: CN=mcpki-dilithium2-root-ca,O=mcpki.org\n-----BEGIN CERTIFICATE-----\nMII..."
	 * 
	 * {
	 *   "ca_chain": "Subject: CN=mcpki-rsa-sub-ca,O=mcpki.org\nIssuer: CN=mcpki-rsa-root-ca,O=mcpki.org\n-----BEGIN CERTIFICATE-----\nMIICSzCCAbSg ... 7cuYeSxA==\n-----END CERTIFICATE-----\n",
  	 *   "error_code": 400,
  	 *   "error_message": "CA with ID 928271178 doesn't exist."
	 * }
	 */
	// @formatter:on
	record GetCaCertificateResponse(String ca_chain, String error_code, String error_message) {
	}
}

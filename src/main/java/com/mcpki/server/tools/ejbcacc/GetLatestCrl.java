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
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.mcpki.server.util.PemUtil;
import com.mcpki.server.util.ValidationUtil;

import io.modelcontextprotocol.spec.McpError;

/**
 * MPC Tool to get the latest CRL for an issuer.
 */
@Service
public class GetLatestCrl {

	private static final Logger log = LoggerFactory.getLogger(GetLatestCrl.class);

	@Value("${com.mcpki.server.tools.ejbca.rest.url}")
	private String baseUrl;

	@Value("${com.mcpki.server.pem.length.min}")
	private int pemMinStrength;

	@Value("${com.mcpki.server.pem.length.max}")
	private int pemMaxStrength;

	@Value("${com.mcpki.server.dn.length.min}")
	private int dnMinLength;

	@Value("${com.mcpki.server.dn.length.max}")
	private int dnMaxLength;

	@Autowired
	@Qualifier("tls")
	public RestTemplate restTemplate;

	/**
	 * Returns the latest Certificate Revocation List (CRL) for the given issuer.
	 * 
	 * @param issuer_dn the issuer DN.
	 * @return the CRL.
	 */
	@Tool(name = "get_latest_crl", description = "Get latest CRL.")
	public GetLatestCrlResponse ejbca_getLatestCrl(
			@ToolParam(description = "The subject DN of the issuing CA.") final String issuer_dn) throws McpError
	{
		ValidationUtil.assertValidIssuerDn(issuer_dn, dnMinLength, dnMaxLength);

		final String url = baseUrl + "/v1/ca/" + issuer_dn + "/getLatestCrl?deltaCrl=false?crlPartitionIndex=0";
		if (log.isDebugEnabled()) {
			log.debug("Requested URL: " + url);
		}

		final GetLatestCrlResponse payload = restTemplate.getForObject(url, GetLatestCrlResponse.class);
		String formattedCrl;
		if (payload.crl() != null && !"null".equalsIgnoreCase(payload.crl()) && ValidationUtil
				.isValidPem(formattedCrl = PemUtil.toPemCrl(payload.crl()), pemMinStrength, pemMaxStrength)) {
			return new GetLatestCrlResponse(formattedCrl, "PEM");
		} else {
			return new GetLatestCrlResponse("null", "PEM");
		}
	}

	// @formatter:off
	/**
	 * {
  	 *   "crl": "TUlJRVYuLi5TcVFQRQ==",
  	 *   "response_format": "DER"
	 * }
	 * 
	 * {
  	 *   "crl": null,
  	 *   "response_format": "DER"
	 * }
	 */
	// @formatter:on
	record GetLatestCrlResponse(String crl, String response_format) {
	}
}

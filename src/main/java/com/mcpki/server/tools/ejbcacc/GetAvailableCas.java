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
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import com.mcpki.server.util.McpUtil;

/**
 * MCP tool to get a list of available Certification Authorities (CA).
 */
@Service
public class GetAvailableCas {

	private static final Logger log = LoggerFactory.getLogger(GetAvailableCas.class);

	@Value("${com.mcpki.server.tools.ejbca.rest.url}")
	private String baseUrl;

	@Autowired
	@Qualifier("tls")
	public RestTemplate restTemplate;

	/**
	 * Returns the list of available Certification Authorities (CA).
	 * 
	 * @param external true if external CA are returned.
	 * @return the list of available CAs.
	 */
	@Tool(name = "get_available_cas", description = "Get the list of available CAs.")
	public GetAvailableCasResponse ejbca_getCas(
			@ToolParam(description = "True if external CAs a returned also.") final boolean external)
	{
		final String url = baseUrl + "/v1/ca?includeExternal=" + external;
		try {
			final GetAvailableCasResponse payload = restTemplate.getForObject(url, GetAvailableCasResponse.class);
			if (log.isDebugEnabled()) {
				if (payload.certificate_authorities != null) {
					for (CaResponse response : payload.certificate_authorities) {
						log.debug("CA: {}, expires at {}.", response.name, response.expiration_date);
					}
				}
			}
			return payload;
		} catch (RestClientException e) {
			// Connection refused and others land here, so sanitize response.
			return new GetAvailableCasResponse(null, McpUtil.sanitizeResponse(e.getMessage(), baseUrl));
		}
	}

	// @formatter:off
	/**
	 * "certificate_authorities": [
     * {
     *   "id": 				-685930754,
     *   "name": 			"mcpki-dilithium2-root-ca",
     *   "subject_dn": 		"CN=mcpki-dilithium2-root-ca,O=mcpki.org",
     *   "issuer_dn": 		"CN=mcpki-dilithium2-root-ca,O=mcpki.org",
     *   "expiration_date": "2030-07-02T14:34:15Z"
     *   "external": 		false,
     * }
	 * ]}
	 */
	// @formatter:on
	record GetAvailableCasResponse(CaResponse[] certificate_authorities, String error_message) {
	}

	record CaResponse(long id, String name, String subject_dn, String issuer_dn, String expiration_date,
			boolean external) {
	}
}

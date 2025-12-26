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

/**
 * MCP tool to count the number of certificates.
 */
@Service
public class GetCountCertificates {

	private static final Logger log = LoggerFactory.getLogger(GetCountCertificates.class);

	@Value("${com.mcpki.server.tools.ejbca.rest.url}")
	private String baseUrl;

	@Autowired
	@Qualifier("tls")
	public RestTemplate restTemplate;

	/**
	 * Returns the number certificates in the database.
	 * 
	 * Response: { count: n }
	 * 
	 * @param active true if an active certificates should be counted only.
	 * @return the number of certificates.
	 */
	@Tool(name = "get_count_certificates", description = "Counts the certificates.")
	public String ejbca_getCountCertificates(
			@ToolParam(description = "True for active certificates only.") boolean active)
	{
		final String url = baseUrl + "/v2/certificate/count?isActive=" + active;
		if (log.isDebugEnabled()) {
			log.debug("Call count certificates: {}", url);
		}
		final String response = restTemplate.getForObject(url, String.class);
		return response;
	}
}

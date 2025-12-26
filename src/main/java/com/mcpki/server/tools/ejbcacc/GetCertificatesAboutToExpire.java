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
 * MCP tool to get the list of certificates about to expire.
 */
@Service
public class GetCertificatesAboutToExpire {

	private static final Logger log = LoggerFactory.getLogger(GetCertificatesAboutToExpire.class);

	@Value("${com.mcpki.server.tools.ejbca.rest.url}")
	private String baseUrl;

	@Value("${com.mcpki.server.tools.ejbca.GetCertificatesAboutToExpire.max.items:100}")
	private int maxItems;

	@Autowired
	@Qualifier("tls")
	public RestTemplate restTemplate;

	/**
	 * Return the certificates about to expire within the given time in days.
	 * 
	 * @param days   the number of days
	 * @param offset the list offset
	 * @param max    the maximum number of results per page
	 * @return the list certificates about to expire
	 */
	@Tool(name = "get_certificates_about_to_expire", description = "Get certificates about to expire.")
	public String ejbca_getCertificatesAboutToExpire(
			@ToolParam(description = "Number of days until expiration.") int days,
			@ToolParam(description = "List offset (often 0).") int offset,
			@ToolParam(description = "Maximum number of items returned (max 100).") int max)
	{
		if (days < 0) {
			days = 0;
		}
		if (offset < 0) {
			offset = 0;
		}
		if (max > maxItems) {
			max = maxItems;
		}
		final String url = baseUrl + "/v1/certificate/expire?days=" + days + "&offset=" + offset
				+ "&maxNumberOfResults=" + max;
		if (log.isDebugEnabled()) {
			log.debug("Requested URL: {}", url);
		}

		final String response = restTemplate.getForObject(url, String.class);
		return response;
	}
}

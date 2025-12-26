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
import com.mcpki.server.util.ValidationUtil;

/**
 * MCP tool to get a certificate profile detail information.
 */
@Service
public class GetCertificateProfile {

	private static final Logger log = LoggerFactory.getLogger(GetCertificateProfile.class);

	@Value("${com.mcpki.server.tools.ejbca.rest.url}")
	private String baseUrl;

	@Value("${com.mcpki.server.name.length.min}")
	private int nameMinLength;

	@Value("${com.mcpki.server.name.length.max}")
	private int nameMaxLength;

	@Autowired
	@Qualifier("tls")
	public RestTemplate restTemplate;

	/**
	 * Returns the certificate profile with the given name.
	 * 
	 * @param name the name
	 * @return the certificate profile
	 */
	@Tool(name = "get_certificate_profile", description = "Get certificate profile.")
	public String ejbca_getCertificateProfile(
			@ToolParam(description = "The name of the certificate profile.") final String name)
	{
		ValidationUtil.assertValidName("certificateProfileName", name, nameMinLength, nameMaxLength);

		final String url = baseUrl + "/v2/certificate/profile/" + name;
		if (log.isDebugEnabled()) {
			log.debug("Requested URL: " + url);
		}

		try {
			final String payload = restTemplate.getForObject(url, String.class);
			return payload;
		} catch (RestClientException e) {
			// Connection refused and others land here, so sanitize response.
			return McpUtil.sanitizeResponse(e.getMessage(), baseUrl);
		}
	}
}

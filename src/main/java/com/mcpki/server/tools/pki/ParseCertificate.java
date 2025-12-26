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

package com.mcpki.server.tools.pki;

import java.io.IOException;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.mcpki.server.util.McpUtil;
import com.mcpki.server.util.PemUtil;
import com.mcpki.server.util.ValidationUtil;

import io.modelcontextprotocol.spec.McpError;

@Service
public class ParseCertificate {

	private static final Logger log = LoggerFactory.getLogger(ParseCertificate.class);

	@Value("${com.mcpki.server.pem.length.min}")
	private int pemMinStrength;

	@Value("${com.mcpki.server.pem.length.max}")
	private int pemMaxStrength;

	/**
	 * Returns the certificate in human readable form.
	 * 
	 * @param issuerDn the issuer DN.
	 * @return the certificate.
	 */
	@Tool(name = "parse_certificate", description = "Parses a certificate.")
	public String pki_parseCertificate(
			@ToolParam(description = "The PEM formatted X.509 certificate.") final String certificate) throws McpError
	{
		ValidationUtil.assertValidPem("certificate", certificate, pemMinStrength, pemMaxStrength);

		if (log.isDebugEnabled()) {
			log.debug("Parse PEM certificate: " + certificate);
		}

		try {
			final String result = PemUtil.parsePemCertificate(certificate);
			if (log.isDebugEnabled()) {
				log.debug("Parsed certificate: " + result);
			}
			return result;
		} catch (IOException e) {
			e.printStackTrace();
			throw McpUtil.invalidParamsError("Failed to parse PEM certificate.", Map.of("certificate", certificate));
		}
	}
}

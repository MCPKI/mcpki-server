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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class for PEM formatting and parsing.
 */
public class PemUtil {

	private static final Logger log = LoggerFactory.getLogger(PemUtil.class);

	private static final int CHUNK_SIZE = 64;

	private static final String CRL_BOUNDARY_START = "-----BEGIN X509 CRL-----\n";

	private static final String CRL_BOUNDARY_END = "-----END X509 CRL-----";

	private static final String CERTIFICATE_BOUNDARY_START = "-----BEGIN CERTIFICATE-----\n";

	private static final String CERTIFICATE_BOUNDARY_END = "-----END CERTIFICATE-----";

	/**
	 * Converts a base64 formatted CRL to PEM including boundaries.
	 * 
	 * @param base64Content the base64 formatted CRL.
	 * @return the PEM formatted CRL.
	 */
	public static final String toPemCrl(final String base64Content)
	{
		return CRL_BOUNDARY_START + toPem(base64Content) + CRL_BOUNDARY_END;
	}

	/**
	 * Converts a base64 formatted X.509 certificate to PEM including boundaries.
	 * 
	 * @param base64Content the base64 formatted certificate.
	 * @return the PEM formatted certificate.
	 */
	public static final String toPemCertificate(final String base64Content)
	{
		return CERTIFICATE_BOUNDARY_START + toPem(base64Content) + CERTIFICATE_BOUNDARY_END;
	}

	/**
	 * Converts a base64 formatted string to PEM.
	 * 
	 * @param base64Content the base64 formatted string.
	 * @return the PEM formatted string.
	 */
	public static final String toPem(final String base64Content)
	{
		final StringBuilder sb = new StringBuilder();
		for (int i = 0; i < base64Content.length(); i += CHUNK_SIZE) {
			sb.append(base64Content.substring(i, Math.min(i + CHUNK_SIZE, base64Content.length()))).append("\n");
		}
		return sb.toString();
	}

	/**
	 * Parses a PEM formatted X.509 certificate string and returns its string
	 * representation.
	 *
	 * @param pem the PEM formatted certificate string.
	 * @return the string representation of the parsed certificate, or an empty
	 *         string if parsing fails.
	 * @throws IOException in case of I/O errors during processing.
	 */
	public static final String parsePemCertificate(final String pem) throws IOException
	{
		try {
			final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			final X509Certificate certificate = (X509Certificate) certFactory
					.generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
			return certificate.toString();
		} catch (Exception e) {
			log.info("Failed to parse certificate: {}.", e.getMessage());
			e.printStackTrace();
		}

		return "";
	}

}

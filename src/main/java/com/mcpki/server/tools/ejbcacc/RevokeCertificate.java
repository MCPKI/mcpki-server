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

import java.util.Date;
import java.util.Map;
import java.util.TreeMap;

import org.json.simple.JSONObject;
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
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import com.mcpki.server.util.ValidationUtil;

/**
 * MCP tool to revoke a certificate.
 */
@Service
public class RevokeCertificate {

	private static final Logger log = LoggerFactory.getLogger(RevokeCertificate.class);

	@Value("${com.mcpki.server.tools.ejbca.rest.url}")
	private String baseUrl;

	@Value("${com.mcpki.server.password.strength.min}")
	private int pwdMinStrength;

	@Value("${com.mcpki.server.password.strength.max}")
	private int pwdMaxStrength;

	@Value("${com.mcpki.server.password.allowedCharacters}")
	private String pwdAllowedCharacters;

	@Value("${com.mcpki.server.dn.length.min}")
	private int dnMinLength;

	@Value("${com.mcpki.server.dn.length.max}")
	private int dnMaxLength;

	@Value("${com.mcpki.server.serialnumber.hex.length}")
	private int serialNumberLength;

	@Autowired
	@Qualifier("tls")
	public RestTemplate restTemplate;

	/**
	 * This method revokes a certificate.
	 * 
	 * @param issuer_dn         the subject DN of the issuing CA
	 * @param serial_number     the serial number of the certificate in hex
	 * @param password          the password used to enroll the certificate
	 * @param revocation_reason the revocation reason
	 * @return a confirmation message if the certificate has been revoked or an
	 *         error message otherwise.
	 */
	@Tool(name = "revoke_certificate", description = "Revoked a certificate.")
	public RevokeCertificateResponse ejbca_revokeCertificate(
			@ToolParam(description = "The issuer of the certificate.") String issuer_dn,
			@ToolParam(description = "The certificate serial number in hex format.") String serial_number,
			@ToolParam(description = "The certificate password.") String password,
			@ToolParam(description = "The revocation reason.") String revocation_reason)
	{
		ValidationUtil.assertValidSerialNumberHex(serial_number, serialNumberLength);
		ValidationUtil.assertValidIssuerDn(issuer_dn, dnMinLength, dnMaxLength);
		ValidationUtil.assertValidPassword(password, pwdMinStrength, pwdMaxStrength, pwdAllowedCharacters);
		ValidationUtil.assertValidRevocationReason(revocation_reason);

		final String url = baseUrl + "/v1/certificate/" + issuer_dn + "/" + serial_number + "/revoke?reason="
				+ revocation_reason;
		if (log.isDebugEnabled()) {
			log.debug("Requested URL: " + url);
		}

		final Map<String, Object> param = new TreeMap<>();
		param.put("password", password);
		final JSONObject json = new JSONObject(param);

		try {
			final HttpHeaders headers = new HttpHeaders();
			headers.setContentType(MediaType.APPLICATION_JSON);
			final HttpEntity<String> request = new HttpEntity<String>(json.toJSONString(), headers);
			final RevokeCertificateResponse response = restTemplate.postForObject(url, request,
					RevokeCertificateResponse.class);
			return response;
		} catch (RestClientException e) {
			if (log.isDebugEnabled()) {
				log.debug("Could not revoked certificate with SN {} issued by {} with revocation reason {}: {}",
						serial_number, issuer_dn, revocation_reason, e.getMessage());
			}
			return new RevokeCertificateResponse(false, issuer_dn, serial_number, null, revocation_reason,
					"Certificate could not be revoked. Either the certificate does not exist, the password is "
							+ "tempered or the revocation reason is invalid.");
		}
	}

	// @formatter:off
	/**
     * {
     *   "revoked"				true
     *   "issuer_dn": 			"CN=mcpki-rsa-sub-ca,O=mcpki.org",
     *   "serial_number":		"3317571EB0DF61426A1A6A380DB03C23A1266E8E"
     *   "revocation_date": 	"1756722738000",
     *   "revocation_reason": 	"UNSPECIFIED",
     *   "message":				"Successfully revoked"
     * }
     * 
     * {
     *  "revoked":				false,
     *  "message":				"Certificate could not be revoked. Either the 
     *  						 certificate does not exist, the password is 
     *  						 tempered or the revocation reason is invalid."
     * }
	 */
	// @formatter:on
	record RevokeCertificateResponse(boolean revoked, String issuer_dn, String serial_number, Date revocation_date,
			String revocation_reason, String message) {
	}
}

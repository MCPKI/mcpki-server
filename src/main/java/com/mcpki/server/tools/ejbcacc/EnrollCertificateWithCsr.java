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

import com.mcpki.server.util.McpUtil;
import com.mcpki.server.util.PemUtil;
import com.mcpki.server.util.ValidationUtil;

/**
 * MCP tool to enroll a certificate with a Certificate Signing Request (CSR).
 */
@Service
public class EnrollCertificateWithCsr {

	private static final Logger log = LoggerFactory.getLogger(EnrollCertificateWithCsr.class);

	@Value("${com.mcpki.server.tools.ejbca.rest.url}")
	private String baseUrl;

	@Value("${com.mcpki.server.email.length.min}")
	private int emailMinLength;

	@Value("${com.mcpki.server.email.length.max}")
	private int emailMaxLength;

	@Value("${com.mcpki.server.name.length.min}")
	private int nameMinLength;

	@Value("${com.mcpki.server.name.length.max}")
	private int nameMaxLength;

	@Value("${com.mcpki.server.password.strength.min}")
	private int pwdMinStrength;

	@Value("${com.mcpki.server.password.strength.max}")
	private int pwdMaxStrength;

	@Value("${com.mcpki.server.pem.length.min}")
	private int pemMinStrength;

	@Value("${com.mcpki.server.pem.length.max}")
	private int pemMaxStrength;

	@Value("${com.mcpki.server.password.allowedCharacters}")
	private String pwdAllowedCharacters;

	@Autowired
	@Qualifier("tls")
	public RestTemplate restTemplate;

	/**
	 * Enrolls a certificate given the PKCS#10 Certificate Signing Request (CSR) and
	 * return it in the PEM format.
	 * 
	 * @param csr                      the CSR.
	 * @param certificate_profile_name the certificate profile name.
	 * @param end_entity_profile_name  the end entity profile name.
	 * @param name_of_ca               the CA name.
	 * @param username                 the username.
	 * @param password                 the user password.
	 * @param includeChain             include the CA certificate chain.
	 * @param email                    the user e-mail address.
	 * @return the PEM formatted certificate.
	 */
	@Tool(name = "enroll_certificate_with_csr", description = "Enrolls a certificate given a CSR.")
	public EnrollCertificateWithCsrResponse ejbca_enrollPkcs10(
			@ToolParam(description = "Certificate Signing Request (CSR)") final String csr,
			@ToolParam(description = "Name of the certificate profile.") final String certificate_profile_name,
			@ToolParam(description = "Name of the end entity profile.") final String end_entity_profile_name,
			@ToolParam(description = "Name of the issuing CA.") final String name_of_ca,
			@ToolParam(description = "Name of the end entity.") final String username,
			@ToolParam(description = "Password of the end entity.") final String password,
			@ToolParam(description = "Email of the end entity.") final String email)
	{
		final String url = baseUrl + "/v1/certificate/pkcs10enroll";

		if (log.isDebugEnabled()) {
			log.debug("Requested URL: " + url);
		}
		if (log.isDebugEnabled()) {
			log.debug("CSR: " + csr);
		}

		final HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);

		ValidationUtil.assertValidPassword(password, pwdMinStrength, pwdMaxStrength, pwdAllowedCharacters);
		ValidationUtil.assertValidName("certificateProfileName", certificate_profile_name, nameMinLength,
				nameMaxLength);
		ValidationUtil.assertValidName("endEntityProfileName", end_entity_profile_name, nameMinLength, nameMaxLength);
		ValidationUtil.assertValidName("username", username, nameMinLength, nameMaxLength);
		ValidationUtil.assertValidEmail(email, emailMinLength, emailMaxLength);
		ValidationUtil.assertValidPem("csr", csr, pemMinStrength, pemMaxStrength);

		final Map<String, Object> param = new TreeMap<>();
		param.put("certificate_request", csr);
		param.put("certificate_profile_name", certificate_profile_name);
		param.put("end_entity_profile_name", end_entity_profile_name);
		param.put("certificate_authority_name", name_of_ca);
		param.put("username", username);
		param.put("password", password);
		param.put("include_chain", Boolean.toString(false));
		param.put("email", email);
		param.put("reponse_format", "PEM");
		final JSONObject json = new JSONObject(param);

		final HttpEntity<String> request = new HttpEntity<String>(json.toJSONString(), headers);
		EnrollCertificateWithCsrResponse payload;

		try {
			payload = restTemplate.postForObject(url, request, EnrollCertificateWithCsrResponse.class);
			final String pem = PemUtil.toPemCertificate(payload.certificate());
			if (log.isDebugEnabled()) {
				log.debug("Generated certificate: \n{}", pem);
			}
			if (ValidationUtil.isValidPem(pem, pemMinStrength, pemMaxStrength)) {
				return new EnrollCertificateWithCsrResponse(pem, payload.serial_number(), "PEM",
						payload.error_message());
			} else {
				return new EnrollCertificateWithCsrResponse(null, null, null,
						McpUtil.sanitizeResponse("Certificate is invalid PEM format.", baseUrl));
			}
		} catch (RestClientException e) {
			// Connection refused and others land here, so sanitize response.
			// Also others land here:
			// Certificate profile with name abc not found.
			return new EnrollCertificateWithCsrResponse(null, null, null, McpUtil
					.sanitizeResponse(e.getMessage() + " --- " + e.getCause() + " --- " + e.getRootCause(), baseUrl));
		}
	}

	// @formatter:off
	/**
     * {
     *   "certificate": 		"CN=mcpki-dilithium2-root-ca,O=mcpki.org",
     *   "serial_number":		"3317571EB0DF61426A1A6A380DB03C23A1266E8E"
     *   "response_format": 	"PEM",
     *   "error_message": 		"Error...",
     * }
	 */
	// @formatter:on
	record EnrollCertificateWithCsrResponse(String certificate, String serial_number, String format,
			String error_message) {
	}

}

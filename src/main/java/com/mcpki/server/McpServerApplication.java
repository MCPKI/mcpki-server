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

package com.mcpki.server;

import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import com.mcpki.server.tools.ejbcacc.CreateCrl;
import com.mcpki.server.tools.ejbcacc.EnrollCertificateWithCsr;
import com.mcpki.server.tools.ejbcacc.GetAvailableCas;
import com.mcpki.server.tools.ejbcacc.GetCaCertificate;
import com.mcpki.server.tools.ejbcacc.GetCertificateProfile;
import com.mcpki.server.tools.ejbcacc.GetCertificatesAboutToExpire;
import com.mcpki.server.tools.ejbcacc.GetCountCertificates;
import com.mcpki.server.tools.ejbcacc.GetLatestCrl;
import com.mcpki.server.tools.ejbcacc.RevokeCertificate;
import com.mcpki.server.tools.pki.ParseCertificate;

@SpringBootApplication
public class McpServerApplication {

	private static final Logger log = LoggerFactory.getLogger(McpServerApplication.class);

	@Value("${com.mcpki.server.tools.ejbca.GetAvailableCas:false}")
	private boolean loadGetAvailableCas;

	@Value("${com.mcpki.server.tools.ejbca.GetCaCertificate:false}")
	private boolean loadGetCaCertificate;

	@Value("${com.mcpki.server.tools.ejbca.CreateCrl:false}")
	private boolean loadCreateCrl;

	@Value("${com.mcpki.server.tools.ejbca.GetLatestCrl:false}")
	private boolean loadGetLatestCrl;

	@Value("${com.mcpki.server.tools.ejbca.GetCountCertificates:false}")
	private boolean loadGetCountCertificates;

	@Value("${com.mcpki.server.tools.ejbca.GetCertificateProfile:false}")
	private boolean loadGetCertificateProfile;

	@Value("${com.mcpki.server.tools.ejbca.GetCertificatesAboutToExpire:false}")
	private boolean loadGetCertificatesAboutToExpire;

	@Value("${com.mcpki.server.tools.ejbca.EnrollCertificateWithCsr:false}")
	private boolean loadEnrollCertificateWithCsr;

	@Value("${com.mcpki.server.tools.ejbca.RevokeCertificate:false}")
	private boolean loadRevokeCertificate;

	@Value("${com.mcpki.server.tools.pki.ParseCertificate:false}")
	private boolean loadParseCertificate;

	public static void main(String[] args)
	{
		Security.addProvider(new BouncyCastleProvider());
		SpringApplication.run(McpServerApplication.class, args);
	}

	@Bean
	public ToolCallbackProvider loadTools(final GetAvailableCas getAvailableCas,
			final GetCaCertificate getCaCertificate, final GetLatestCrl getLatestCrl, final CreateCrl createCrl,
			final GetCountCertificates getCountCertificates, final GetCertificateProfile getCertificateProfile,
			final GetCertificatesAboutToExpire getCertificatesAboutToExpire,
			final EnrollCertificateWithCsr enrollCertificateWithCsr, final RevokeCertificate revokeCertificate,
			final ParseCertificate parseCertificate)
	{
		final List<Object> services = new ArrayList<Object>();

		if (loadGetAvailableCas) {
			if (log.isDebugEnabled()) {
				log.debug("Loading EJBCA get_available_CAs.");
			}
			services.add(getAvailableCas);
		}
		if (loadGetCaCertificate) {
			if (log.isDebugEnabled()) {
				log.debug("Loading EJBCA get_CA_Certificate.");
			}
			services.add(getCaCertificate);
		}
		if (loadCreateCrl) {
			if (log.isDebugEnabled()) {
				log.debug("Loading EJBCA create_CRL.");
			}
			services.add(createCrl);
		}
		if (loadGetLatestCrl) {
			if (log.isDebugEnabled()) {
				log.debug("Loading EJBCA get_latest_CRL.");
			}
			services.add(getLatestCrl);
		}
		if (loadGetCountCertificates) {
			if (log.isDebugEnabled()) {
				log.debug("Loading EJBCA get_count_certificates.");
			}
			services.add(getCountCertificates);
		}
		if (loadGetCertificateProfile) {
			if (log.isDebugEnabled()) {
				log.debug("Loading EJBCA get_certificate_profile.");
			}
			services.add(getCertificateProfile);
		}
		if (loadGetCertificatesAboutToExpire) {
			if (log.isDebugEnabled()) {
				log.debug("Loading EJBCA get_ertificates_about_to_expire.");
			}
			services.add(getCertificatesAboutToExpire);
		}
		if (loadEnrollCertificateWithCsr) {
			if (log.isDebugEnabled()) {
				log.debug("Loading EJBCA enroll_certificate_with_CSR.");
			}
			services.add(enrollCertificateWithCsr);
		}
		if (loadRevokeCertificate) {
			if (log.isDebugEnabled()) {
				log.debug("Loading EJBCA revoke_certificate.");
			}
			services.add(revokeCertificate);
		}
		if (loadParseCertificate) {
			if (log.isDebugEnabled()) {
				log.debug("Loading EJBCA Parse certificate.");
			}
			log.info("Loading PKI parse_certificate.");
			services.add(parseCertificate);
		}
		return MethodToolCallbackProvider.builder().toolObjects(services.toArray()).build();
	}
}

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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class McpServerApplication {

//	private static final Logger log = LoggerFactory.getLogger(McpServerApplication.class);
//
//	@Value("${com.mcpki.server.tools.ejbca.GetAvailableCas:false}")
//	private boolean loadGetAvailableCas;
//
//	@Value("${com.mcpki.server.tools.ejbca.GetCaCertificate:false}")
//	private boolean loadGetCaCertificate;
//
//	@Value("${com.mcpki.server.tools.ejbca.CreateCrl:false}")
//	private boolean loadCreateCrl;
//
//	@Value("${com.mcpki.server.tools.ejbca.GetLatestCrl:false}")
//	private boolean loadGetLatestCrl;
//
//	@Value("${com.mcpki.server.tools.ejbca.GetCountCertificates:false}")
//	private boolean loadGetCountCertificates;
//
//	@Value("${com.mcpki.server.tools.ejbca.GetCertificateProfile:false}")
//	private boolean loadGetCertificateProfile;
//
//	@Value("${com.mcpki.server.tools.ejbca.GetCertificatesAboutToExpire:false}")
//	private boolean loadGetCertificatesAboutToExpire;
//
//	@Value("${com.mcpki.server.tools.ejbca.EnrollCertificateWithCsr:false}")
//	private boolean loadEnrollCertificateWithCsr;
//
//	@Value("${com.mcpki.server.tools.ejbca.RevokeCertificate:false}")
//	private boolean loadRevokeCertificate;
//
//	@Value("${com.mcpki.server.tools.pki.ParseCertificate:false}")
//	private boolean loadParseCertificate;

	public static void main(String[] args)
	{
		Security.addProvider(new BouncyCastleProvider());
		SpringApplication.run(McpServerApplication.class, args);
	}

}

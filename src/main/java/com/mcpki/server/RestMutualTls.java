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

import java.io.IOException;

import javax.net.ssl.SSLContext;

import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.ResourceUtils;
import org.springframework.web.client.RestTemplate;

@Configuration
public class RestMutualTls {

	@Value("${com.mcpki.server.tools.ejbca.rest.keystore}")
	private String keystore;

	@Value("${com.mcpki.server.tools.ejbca.rest.keystorepwd}")
	private String keystorePwd;

	@Value("${com.mcpki.server.tools.ejbca.rest.truststore}")
	private String truststore;

	@Value("${com.mcpki.server.tools.ejbca.rest.truststorepwd}")
	private String truststorePwd;

	@Bean
	@Qualifier("tls")
	public RestTemplate restTemplate(final RestTemplateBuilder builder) throws Exception
	{
		final SSLContext sslContext = SSLContextBuilder.create()
				.loadKeyMaterial(ResourceUtils.getFile(keystore), keystorePwd.toCharArray(), keystorePwd.toCharArray())
				.loadTrustMaterial(ResourceUtils.getFile(truststore), truststorePwd.toCharArray()).build();

		return new RestTemplate(new MutualTlsRequestFactory(sslContext));
	}

	private static class MutualTlsRequestFactory
			extends org.springframework.http.client.SimpleClientHttpRequestFactory {

		private final SSLContext sslContext;

		public MutualTlsRequestFactory(SSLContext sslContext) {
			this.sslContext = sslContext;
		}

		@Override
		protected void prepareConnection(java.net.HttpURLConnection connection, String httpMethod) throws IOException
		{
			if (connection instanceof javax.net.ssl.HttpsURLConnection) {
				((javax.net.ssl.HttpsURLConnection) connection).setSSLSocketFactory(sslContext.getSocketFactory());
				// ((javax.net.ssl.HttpsURLConnection) connection).setHostnameVerifier((hostname, session) -> true);
				// In a secure production environment, hostname verification should be enabled to ensure
				// that the server being accessed is the intended one and to prevent potential
				// security vulnerabilities
			}
			super.prepareConnection(connection, httpMethod);
		}
	}
}
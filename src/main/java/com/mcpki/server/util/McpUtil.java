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

import java.util.Map;

import org.json.simple.JSONObject;

import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.spec.McpSchema.ErrorCodes;
import io.modelcontextprotocol.spec.McpSchema.JSONRPCResponse.JSONRPCError;

/**
 * Utility class for Model Context Protocol (MPC) related functions.
 */
public class McpUtil {

	/**
	 * Returns an MCP error message of type INVALID_PARAMS = -32602.
	 * 
	 * @param msg    the error message.
	 * @param object the detail object.
	 * 
	 * @return the MPC error.
	 */
	public static final McpError invalidParamsError(final String msg, final String object)
	{
		return new McpError(new JSONRPCError(ErrorCodes.INVALID_PARAMS, msg, object));
	}

	/**
	 * Returns an MCP error message of type INVALID_PARAMS = -32602.
	 * 
	 * @param msg the error message.
	 * @param map the parameter map.
	 * 
	 * @return the MPC error.
	 */
	public static final McpError invalidParamsError(final String msg, final Map<String, Object> map)
	{
		return new McpError(new JSONRPCError(ErrorCodes.INVALID_PARAMS, msg, new JSONObject(map).toJSONString()));
	}

	/**
	 * Returns a masks the given URL in the error message (or other payload).
	 * 
	 * E.g.: I/O error on GET request for
	 * "https://<host>:<port>/ca/CN=mcpki-rsa-sub-ca/certificate/download":
	 * Connection refused
	 * 
	 * @param response the response message or payload.
	 * @param baseUrl  the url
	 * @return the sanitized string.
	 */
	public static String sanitizeResponse(final String response, final String baseUrl)
	{
		if (response.contains(baseUrl)) {
			return response.replace(baseUrl, "https://<host>:<port>/...");
		}
		return response;
	}
}

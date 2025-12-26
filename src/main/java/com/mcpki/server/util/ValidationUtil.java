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

import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.modelcontextprotocol.spec.McpError;

/**
 * Utility class to validate input and output data.
 */
@SuppressWarnings("deprecation")
public class ValidationUtil {

	private static final Logger log = LoggerFactory.getLogger(ValidationUtil.class);

	private static final Pattern DN_PATTERN = Pattern.compile("^[^~?`!|%$;^&{}\0\r\t\n\\\\\"]*$");

	private static final Pattern PEM_PATTERN = Pattern.compile(
			"-----BEGIN ([A-Z0-9 ]+)-----\\s+([a-zA-Z0-9+/=\\r\\n]+)\\s+-----END \\1-----\\s*", Pattern.MULTILINE);

	public static List<String> REVOCATION_REASON = Collections.unmodifiableList(List.of("NOT_REVOKED", "UNSPECIFIED",
			"KEY_COMPROMISE", "CA_COMPROMISE", "AFFILIATION_CHANGED", "SUPERSEDED", "CESSATION_OF_OPERATION",
			"CERTIFICATE_HOLD", "REMOVE_FROM_CRL", "PRIVILEGES_WITHDRAWN", "AA_COMPROMISE"));

	/**
	 * Validates if the given distinguished name (DN) meets length requirements and
	 * matches the pattern.
	 *
	 * @param dn        the distinguished name to validate
	 * @param minLength minimum allowed length of the DN
	 * @param maxLength maximum allowed length of the DN
	 * @return true if the DN is valid, false otherwise
	 */
	public static final boolean isValidDn(final String dn, final int minLength, final int maxLength)
	{
		if (dn == null || dn.isEmpty()) {
			log.warn("DN is null or empty.");
		}
		if (dn.length() < minLength || dn.length() > maxLength) {
			log.warn("DN length out of range: {}.", dn.length());
		}
		if (DN_PATTERN.matcher(dn).matches()) {
			try {
				@SuppressWarnings("unused")
				final X509Name name = new X509Name(dn);
				return true;
			} catch (IllegalArgumentException e) {
				log.warn("Invalid DN: {}.", e.getMessage());
				return false;
			}
		}
		return false;
	}

	/**
	 * Asserts that the provided issuer distinguished name (DN) is valid. If
	 * invalid, logs a debug message and throws an Invalid Parameters error.
	 *
	 * @param dn        the issuer DN to validate
	 * @param minLength minimum allowed length of the issuer DN
	 * @param maxLength maximum allowed length of the issuer DN
	 * @throws McpError if the issuer DN is not valid according to the specified
	 *                  criteria
	 */
	public static void assertValidIssuerDn(final String dn, final int minLength, final int maxLength) throws McpError
	{
		if (!isValidDn(dn, minLength, maxLength)) {
			if (log.isDebugEnabled()) {
				log.debug("Invalid DN: {}.", dn);
			}
			throw McpUtil.invalidParamsError("Invalid DN.", Map.of("dn", dn));
		}
	}

	/**
	 * Checks if the provided string is a valid hexadecimal number.
	 *
	 * @param hex    the string to validate as hexadecimal
	 * @param length the length of the hex string
	 * @return true if the string is a valid hexadecimal representation with the
	 *         given length, false otherwise
	 */
	public static boolean isValidSerialNumberHex(final String hex, final int length)
	{
		if (hex == null || hex.length() != length) {
			return false;
		}
		return hex.matches("^[0-9a-fA-F]+$");
	}

	/**
	 * Asserts that the provided string is a valid hexadecimal representation of a
	 * serial number. If invalid, logs a debug message and throws an Invalid
	 * Parameters error.
	 *
	 * @param hex    the hexadecimal string to validate as a serial number
	 * @param length the expected length of the hex string
	 * @throws McpError if the hex string is not valid according to the specified
	 *                  criteria
	 */
	public static void assertValidSerialNumberHex(final String hex, final int length) throws McpError
	{
		if (!isValidSerialNumberHex(hex, length)) {
			if (log.isDebugEnabled()) {
				log.debug("Invalid serial number hex: {}.", hex);
			}
			throw McpUtil.invalidParamsError("Invalid serial number.", Map.of("hex", hex));
		}
	}

	/**
	 * Asserts that the provided revocation reason is valid. If invalid, logs a
	 * debug message and throws an Invalid Parameters error.
	 *
	 * @param reason the revocation reason to validate
	 * @throws McpError if the reason is null or not in the allowed set of
	 *                  revocation reasons
	 */
	public static void assertValidRevocationReason(final String reason) throws McpError
	{
		if (reason == null || !REVOCATION_REASON.contains(reason)) {
			if (log.isDebugEnabled()) {
				log.debug("Invalid revocation reason: {}.", reason);
			}
			throw McpUtil.invalidParamsError("Invalid revocation reason.", Map.of("revocation_reason", reason));
		}
	}

	/**
	 * Returns true if the given string only contains allowed characters for names
	 * (alphanumeric[lower and upper case] + numbers + underscore, minus, @ and .)
	 * and the length is in the given range.
	 * 
	 * @param string    the string.
	 * @param minLength the minimum length.
	 * @param maxLength the maximum length.
	 * @return true if it is a valid name string.
	 */
	public static final boolean isValidName(final String string, final int minLength, final int maxLength)
	{
		return string.matches("^[a-zA-Z0-9_\\-@\\.]+$") && string.length() >= minLength && string.length() <= maxLength;
	}

	/**
	 * Asserts that the provided name is valid based on specified minimum and
	 * maximum lengths for a given field. If invalid, logs a debug message with the
	 * field and name, and throws an Invalid Parameters error.
	 *
	 * @param field     the name of the field being validated
	 * @param name      the name string to validate
	 * @param minLength the minimum allowed length for the name
	 * @param maxLength the maximum allowed length for the name
	 * @throws McpError if the name is not valid according to the specified criteria
	 */
	public static void assertValidName(final String field, final String name, final int minLength, final int maxLength)
			throws McpError
	{
		if (!isValidName(name, minLength, maxLength)) {
			if (log.isDebugEnabled()) {
				log.debug("Invalid name for field '{}': '{}'.", field, name);
			}
			throw McpUtil.invalidParamsError("Invalid name (" + field + ").", Map.of("name", name));
		}
	}

	/**
	 * Returns true if the given string is a valid e-mail address with the given
	 * range.
	 * 
	 * @param email             the email address string.
	 * @param minLength         the minimum length.
	 * @param maxLength         the maximum length.
	 * @param allowedCharacters the allowed characters.
	 * @return true if it is a valid email string.
	 */
	public static final boolean isValidEmail(final String email, final int minLength, final int maxLength)
	{
		return email.matches(
				"^(?=.{1,64}@)[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)*@[^-][A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*(\\.[A-Za-z]{2,})$")
				&& email.length() >= minLength && email.length() <= maxLength;
	}

	/**
	 * Asserts that the provided email is valid based on specified minimum and
	 * maximum lengths. If invalid, logs a debug message and throws an Invalid
	 * Parameters error with the email as context.
	 *
	 * @param email     the email string to validate
	 * @param minLength the minimum allowed length for the email
	 * @param maxLength the maximum allowed length for the email
	 * @throws McpError if the email is not valid according to the specified
	 *                  criteria
	 */
	public static void assertValidEmail(final String email, final int minLength, final int maxLength) throws McpError
	{
		if (!isValidEmail(email, minLength, maxLength)) {
			if (log.isDebugEnabled()) {
				log.debug("Invalid e-mail: {}.", email);
			}
			throw McpUtil.invalidParamsError("Invalid e-mail.", Map.of("email", email));
		}
	}

	/**
	 * Validates whether a given password meets specific criteria:
	 *
	 * 1. The length of the password is within the specified minimum and maximum
	 * range. 2. The password contains only allowed characters as defined by the
	 * regular expression pattern.
	 *
	 * @param password          the password string to validate.
	 * @param minLength         the minimum required length for the password.
	 * @param maxLength         the maximum allowed length for the password.
	 * @param allowedCharacters the list of allowed characters as string.
	 * @return true if the password meets all criteria, false otherwise.
	 */
	public static final boolean isValidPassword(final String password, final int minLength, final int maxLength,
			final String allowedCharacters)
	{
		if (password.length() < minLength || password.length() > maxLength) {
			log.warn("Password length out of range: {}.", password.length());
			return false;
		}

		if (!hasAllowedCharacters(password, allowedCharacters)) {
			log.warn("Password must only use these characters: {}.", allowedCharacters);
			return false;
		}

		return true;
	}

	/**
	 * Asserts that the provided password is valid based on specified minimum and
	 * maximum lengths, and allowed characters. If invalid, logs a debug message and
	 * throws an Invalid Parameters error.
	 *
	 * @param pwd               the password string to validate
	 * @param minLength         the minimum allowed length for the password
	 * @param maxLength         the maximum allowed length for the password
	 * @param allowedCharacters the set of allowed characters in the password
	 * @throws McpError if the password is not valid according to the specified
	 *                  criteria
	 */
	public static void assertValidPassword(final String pwd, final int minLength, final int maxLength,
			final String allowedCharacters) throws McpError
	{
		if (!isValidPassword(pwd, minLength, maxLength, allowedCharacters)) {
			if (log.isDebugEnabled()) {
				log.debug("Invalid password: {}.", pwd);
			}
			throw McpUtil.invalidParamsError("Invalid password.", Map.of("password", pwd));
		}
	}

	/**
	 * Verifies if all characters in the password are among the allowed characters.
	 *
	 * @param password          the password to check.
	 * @param allowedCharacters string of permitted characters.
	 * @return true if all password chars are allowed, false otherwise.
	 */
	private static boolean hasAllowedCharacters(final String password, final String allowedCharacters)
	{
		final char[] allowed = allowedCharacters.toCharArray();
		for (final char c : password.toCharArray()) {
			if (!Arrays.contains(allowed, c)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Validates whether a given string is a properly formatted PEM
	 * (Privacy-Enhanced Mail) string.
	 *
	 * The validation process includes: 1. Checking if the length of the input
	 * string falls within the specified minimum and maximum lengths. 2. Ensuring
	 * that only allowed characters (ASCII printable characters, line breaks) are
	 * present in the string. 3. Verifying that the string adheres to standard PEM
	 * format boundaries ("-----BEGIN ...", "-----END ...").
	 *
	 * @param pemString The input string to be validated as a PEM formatted string.
	 * @param minLength The minimum allowed length of the PEM string.
	 * @param maxLength The maximum allowed length of the PEM string.
	 * 
	 * @return {@code true} if the input string is a valid, properly formatted PEM
	 *         string; otherwise, {@code false}.
	 */
	public static final boolean isValidPem(final String pemString, final int minLength, final int maxLength)
	{
		if (pemString.length() < minLength || pemString.length() > maxLength) {
			return false;
		}

		if (!isValidPemFormat(pemString)) {
			return false;
		}

		return true;
	}

	/**
	 * Asserts that the provided PEM string is valid based on specified minimum and
	 * maximum lengths. If invalid, logs a debug message and throws an Invalid
	 * Parameters error.
	 *
	 * @param field     the name of the field containing the PEM data (used for
	 *                  logging)
	 * @param pem       the PEM string to validate
	 * @param minLength the minimum allowed length for the PEM string
	 * @param maxLength the maximum allowed length for the PEM string
	 * @throws McpError if the PEM string is not valid according to the specified
	 *                  criteria
	 */
	public static void assertValidPem(final String field, final String pem, final int minLength, final int maxLength)
			throws McpError
	{
		if (!isValidPem(pem, minLength, maxLength)) {
			if (log.isDebugEnabled()) {
				log.debug("Invalid PEM format (" + field + "): {}.", pem);
			}
			throw McpUtil.invalidParamsError("Invalid PEM format (" + field + ").", Map.of(field, pem));
		}
	}

	/**
	 * Validates if the provided string is in PEM format.
	 *
	 * PEM (Privacy-Enhanced Mail) format is commonly used to encode cryptographic
	 * keys and certificates. This method checks if the input string: 1. Starts with
	 * "-----BEGIN", followed by one or more uppercase letters or digits, and then
	 * "REQUEST-----". 2. Contains only valid characters in between: Printable ASCII
	 * characters (space to tilde) and line breaks. 3. Ends with "-----END",
	 * followed by one or more uppercase letters or digits, and then "REQUEST-----".
	 *
	 * This regex pattern is designed to ensure the input string adheres to the
	 * general structure of PEM-encoded objects while allowing for any valid content
	 * between the BEGIN and END markers.
	 *
	 * @param pem The string to validate in PEM format
	 * @return true if the input string matches the general PEM format; false
	 *         otherwise
	 */

	/**
	 * Validates whether a string is in PEM format per RFC 7468.
	 *
	 * @param pem input string
	 * @return true if valid PEM format, false otherwise
	 */
	public static boolean isValidPemFormat(final String pem)
	{
		if (pem == null) {
			return false;
		}

		// Replace literal "\n" with actual newlines
		final String normalized = pem.replace("\\n", "\n").trim();

		final Matcher matcher = PEM_PATTERN.matcher(normalized);
		if (!matcher.matches()) {
			return false;
		}

		// Extract Base64 payload and strip whitespace
		final String base64Content = matcher.group(2).replaceAll("\\s", "");
		try {
			Base64.getDecoder().decode(base64Content);
			return true;
		} catch (IllegalArgumentException e) {
			return false;
		}
	}

}

package com.sap.cloud.security.token.validation.validators;

/**
 * This is represented by "kty" (Key Type) Parameter.
 * https://www.rfc-editor.org/rfc/rfc7518.html#section-6.1
 */
public enum JwtSignatureAlgorithm {
	RS256("RSA", "RS256", "SHA256withRSA")/* , ES256("EC", "ES256", "SHA256withECDSA")// Eliptic curve */;

	private final String type;
	private final String value;
	private final String javaSignatureAlgorithm;

	JwtSignatureAlgorithm(String type, String algorithm, String javaSignatureAlgorithm) {
		this.type = type;
		this.value = algorithm; // jwks, jwt header
		this.javaSignatureAlgorithm = javaSignatureAlgorithm;
	}

	public String value() {
		return value;
	}

	public String javaSignature() {
		return javaSignatureAlgorithm;
	}

	public String type() {
		return type;
	}

	public static JwtSignatureAlgorithm fromValue(String value) {
		for (JwtSignatureAlgorithm algorithm : values()) {
			if (algorithm.value.equals(value)) {
				return algorithm;
			}
		}
		return null;
	}

	public static JwtSignatureAlgorithm fromType(String type) {
		for (JwtSignatureAlgorithm algorithm : values()) {
			if (algorithm.type.equals(type)) {
				return algorithm;
			}
		}
		return null;
	}
}

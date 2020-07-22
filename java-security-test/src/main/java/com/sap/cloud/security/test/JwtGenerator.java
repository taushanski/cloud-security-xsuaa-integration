package com.sap.cloud.security.test;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.token.validation.validators.JwtSignatureAlgorithm;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.security.PrivateKey;
import java.time.Instant;

/**
 * Jwt {@link Token} builder class to generate tokes for testing purposes.
 * TODO deprecate doc
 * TODO no breaking change, deprecate JwtGenerator.
 * TODO use delegation instead of inheritance!
 */
public class JwtGenerator {
	public static final Instant NO_EXPIRE_DATE = JwtBuilder.NO_EXPIRE_DATE;

	private final Service service;
	private final JwtBuilder jwtBuilder;

	public JwtGenerator(Service service, JwtBuilder jwtBuilder) {

		this.service = service;
		this.jwtBuilder = jwtBuilder;
	}

	public static JwtGenerator getInstance(Service service, String clientId) {
		return new JwtGenerator(service, JwtBuilder.getInstance(service, clientId));
	}

	/**
	 * Builds and signs the token using the the algorithm set via
	 * {@link #withSignatureAlgorithm(JwtSignatureAlgorithm)} and the given key. By
	 * default{@link JwtSignatureAlgorithm#RS256} is used.
	 *
	 * @return the token.
	 */
	public Token createToken() {
		switch (service) {
		case IAS:
			return new SapIdToken(jwtBuilder.createEncodedToken());
		case XSUAA:
			return new XsuaaToken(jwtBuilder.createEncodedToken());
		default:
			throw new UnsupportedOperationException("Identity Service " + service + " is not supported.");
		}
	}

	public JwtGenerator withHeaderParameter(String parameterName, String value) {
		jwtBuilder.withHeaderParameter(parameterName, value);
		return this;
	}

	public JwtGenerator withClaimValue(String claimName, String value) {
		jwtBuilder.withClaimValue(claimName, value);
		return this;
	}

	public JwtGenerator withClaimValue(String claimName, JsonObject object) {
		jwtBuilder.withClaimValue(claimName, object);
		return this;
	}

	public JwtGenerator withClaimValues(String claimName, String... values) {
		jwtBuilder.withClaimValues(claimName, values);
		return this;
	}

	public JwtGenerator withClaimsFromFile(String claimsJsonResource) throws IOException {
		jwtBuilder.withClaimsFromFile(claimsJsonResource);
		return this;
	}

	public JwtGenerator withExpiration(@Nonnull Instant expiration) {
		jwtBuilder.withExpiration(expiration);
		return this;
	}

	public JwtGenerator withSignatureAlgorithm(
			JwtSignatureAlgorithm signatureAlgorithm) {
		jwtBuilder.withSignatureAlgorithm(signatureAlgorithm);
		return this;
	}

	public JwtGenerator withPrivateKey(PrivateKey privateKey) {
		jwtBuilder.withPrivateKey(privateKey);
		return this;
	}

	public JwtGenerator withScopes(String... scopes) {
		jwtBuilder.withScopes(scopes);
		return this;
	}

	public JwtGenerator withLocalScopes(String... scopes) {
		jwtBuilder.withLocalScopes(scopes);
		return this;
	}

	public JwtGenerator withAppId(String appId) {
		jwtBuilder.withAppId(appId);
		return this;
	}
}

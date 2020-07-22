package com.sap.cloud.security.test;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Tests for JwtBuilder specific funtionality.
 * TODO most tests are in JwtGenerator
 */
public class JwtBuilderTest {
	private RSAKeys keys = RSAKeys.generate();
	private JwtBuilder cut;

	@Test
	public void withPrivateKey_usesPrivateKey() throws Exception {
		JwtBuilder.SignatureCalculator signatureCalculator = Mockito.mock(JwtBuilder.SignatureCalculator.class);

		when(signatureCalculator.calculateSignature(any(), any(), any())).thenReturn("sig".getBytes());

		JwtBuilder.getInstance(IAS, signatureCalculator, "T00001234").withPrivateKey(keys.getPrivate())
				.createEncodedToken();

		verify(signatureCalculator, times(1)).calculateSignature(eq(keys.getPrivate()), any(), any());
	}

	@Test
	public void createToken_signatureCalculation_NoSuchAlgorithmExceptionTurnedIntoRuntimeException() {
		String message = "No such algorithm!";

		JwtBuilder cut = JwtBuilder.getInstance(XSUAA, (key, alg, data) -> {
			throw new NoSuchAlgorithmException(message);
		}, "sb-client!1234").withPrivateKey(keys.getPrivate());

		assertThatThrownBy(() -> cut.createEncodedToken())
				.isInstanceOf(RuntimeException.class)
				.hasMessageContaining(message);
	}

	@Test
	public void createToken_signatureCalculation_SignatureExceptionTurnedIntoRuntimeException() {
		String message = "Signature validating failed!";

		cut = JwtBuilder.getInstance(XSUAA, (key, alg, data) -> {
			throw new SignatureException(message);
		}, "sb-client!1234").withPrivateKey(keys.getPrivate());

		assertThatThrownBy(() -> cut.createEncodedToken())
				.isInstanceOf(RuntimeException.class)
				.hasMessageContaining(message);
	}

	@Test
	public void createToken_signatureCalculation_InvalidKeyExceptionTurnedIntoRuntimeException() {
		String message = "Invalid key!";

		cut = JwtBuilder.getInstance(XSUAA, (key, alg, data) -> {
			throw new InvalidKeyException(message);
		}, "sb-client!1234").withPrivateKey(keys.getPrivate());

		assertThatThrownBy(() -> cut.createEncodedToken())
				.isInstanceOf(RuntimeException.class)
				.hasMessageContaining(message);
	}
}
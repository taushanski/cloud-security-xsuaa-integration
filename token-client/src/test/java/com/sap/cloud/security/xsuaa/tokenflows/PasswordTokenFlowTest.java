package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.xsuaa.client.*;
import org.assertj.core.util.Maps;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Map;

import static com.sap.cloud.security.xsuaa.tokenflows.TestConstants.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class PasswordTokenFlowTest {

	private OAuth2TokenService tokenService;
	private OAuth2ServiceEndpointsProvider endpointsProvider;
	private PasswordTokenFlow cut;

	@Before
	public void setUp() throws OAuth2ServiceException {
		tokenService = Mockito.mock(OAuth2TokenService.class);
		endpointsProvider = Mockito.mock(OAuth2ServiceEndpointsProvider.class);

		when(endpointsProvider.getTokenEndpoint()).thenReturn(TOKEN_ENDPOINT_URI);

		cut = new PasswordTokenFlow(tokenService, endpointsProvider, CLIENT_CREDENTIALS);
	}

	@Test
	public void tokenServiceIsNull_throwsException() {
		assertThatThrownBy(() -> new PasswordTokenFlow(null, endpointsProvider, CLIENT_CREDENTIALS))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("OAuth2TokenService");
	}

	@Test
	public void endpointsProviderIsNull_throwsException() {
		assertThatThrownBy(() -> new PasswordTokenFlow(tokenService, null, CLIENT_CREDENTIALS))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("OAuth2ServiceEndpointsProvider");
	}

	@Test
	public void clientCredentialsAreNull_throwsException() {
		assertThatThrownBy(() -> new PasswordTokenFlow(tokenService, endpointsProvider, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("ClientCredentials");
	}

	@Test
	public void execute_usernameIsMissing_throwsException() {
		PasswordTokenFlow passwordTokenFlow = new PasswordTokenFlow(tokenService, endpointsProvider,
				CLIENT_CREDENTIALS);
		assertThatThrownBy(() -> passwordTokenFlow.password(PASSWORD).execute())
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("Username");
	}

	@Test
	public void execute_passwordIsMissing_throwsException() {
		PasswordTokenFlow passwordTokenFlow = new PasswordTokenFlow(tokenService, endpointsProvider,
				CLIENT_CREDENTIALS);
		assertThatThrownBy(() -> passwordTokenFlow.username(USERNAME).execute())
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("Password");
	}

	@Test
	public void execute_returnsCorrectAccessTokenInResponse() throws Exception {
		returnValidResponse();

		OAuth2TokenResponse actualResponse = executeRequest();

		assertThat(actualResponse.getAccessToken()).isEqualTo(ACCESS_TOKEN);
	}

	@Test
	public void execute_ReturnsDifferentAccessTokenInResponse() throws Exception {
		String otherAccessToken = "qwertyqwerty";
		returnValidResponse(otherAccessToken);

		OAuth2TokenResponse actualResponse = executeRequest();

		assertThat(actualResponse.getAccessToken()).isEqualTo(otherAccessToken);
	}

	@Test
	public void execute_ReturnsRefreshTokenInResponse() throws Exception {
		returnValidResponse();

		OAuth2TokenResponse actualResponse = executeRequest();

		assertThat(actualResponse.getRefreshToken()).isEqualTo(REFRESH_TOKEN);
	}

	@Test
	public void allRequiredParametersAreUsed() throws Exception {
		executeRequest();

		Mockito.verify(tokenService, times(1))
				.retrieveAccessTokenViaPasswordGrant(eq(TOKEN_ENDPOINT_URI), eq(CLIENT_CREDENTIALS), eq(
						USERNAME),
						eq(PASSWORD), any(), any());
	}

	@Test
	public void subdomainIsUsed() throws Exception {
		String newSubdomain = "staging";
		createValidRequest().subdomain(newSubdomain).execute();

		Mockito.verify(tokenService, times(1))
				.retrieveAccessTokenViaPasswordGrant(any(), any(), any(),
						any(), eq(newSubdomain), any());
	}

	@Test
	public void additionalParametersAreUsed() throws Exception {
		String key = "aKey";
		String value = "aValue";
		Map<String, String> givenParameters = Maps.newHashMap(key, value);
		Map<String, String> equalParameters = Maps.newHashMap(key, value);

		createValidRequest().optionalParameters(givenParameters).execute();

		Mockito.verify(tokenService, times(1))
				.retrieveAccessTokenViaPasswordGrant(any(), any(), any(),
						any(), any(), eq(equalParameters));
	}

	private OAuth2TokenResponse executeRequest() throws TokenFlowException {
		return createValidRequest().execute();
	}

	private PasswordTokenFlow createValidRequest() {
		return cut.username(USERNAME).password(PASSWORD);
	}

	private void returnValidResponse() throws OAuth2ServiceException {
		OAuth2TokenResponse validResponse = new OAuth2TokenResponse(ACCESS_TOKEN, EXPIRED_IN, REFRESH_TOKEN);
		when(tokenService.retrieveAccessTokenViaPasswordGrant(TOKEN_ENDPOINT_URI, CLIENT_CREDENTIALS, USERNAME,
				PASSWORD,
				null, null))
						.thenReturn(validResponse);
	}

	private void returnValidResponse(String accessToken) throws OAuth2ServiceException {
		OAuth2TokenResponse validResponse = new OAuth2TokenResponse(accessToken, EXPIRED_IN, REFRESH_TOKEN);
		when(tokenService.retrieveAccessTokenViaPasswordGrant(TOKEN_ENDPOINT_URI, CLIENT_CREDENTIALS, USERNAME,
				PASSWORD,
				null, null))
						.thenReturn(validResponse);
	}
}
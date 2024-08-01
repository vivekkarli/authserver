package com.authserver.configurations;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.PasswordLookup;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class AuthServerConfig {

	@Autowired
	private UserDetailsService userDetailsService;

	@Value("${keyFile}")
	private String keyFile;

	@Value("${password}")
	private String password;

	@Value("${alias}")
	private String alias;
	
	@Value("${issuerUrl}")
	private String issuerUrl;
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authSecurityFilterChain(HttpSecurity http) throws Exception {

		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

		return http.userDetailsService(userDetailsService).formLogin(Customizer.withDefaults()).build();
	}

	@Bean
	public JWKSet buildJwkSet() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore keyStore = KeyStore.getInstance("pkcs12");

		try (InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream(keyFile);) {

			keyStore.load(inputStream, alias.toCharArray());

			return JWKSet.load(keyStore, new PasswordLookup() {

				@Override
				public char[] lookupPassword(String name) {
					return password.toCharArray();
				}
			});
		}

	}

	@Bean
	public JWKSource<SecurityContext> jwkSource()
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {

		JWKSet jwkSet = buildJwkSet();
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);

	}
	
	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
		
	}
	
	@Bean
	AuthorizationServerSettings authorizationServerSettings() {
		
		return AuthorizationServerSettings.builder().issuer(issuerUrl).build();
		
		
		
	}
	
	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		RegisteredClient registeredClient = RegisteredClient.withId("story-view")
				.clientId("story-view")
				.clientSecret(bCryptPasswordEncoder.encode("9999"))
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.redirectUri("https://oidcdebugger.com/debug")
				.scope("read")
				.scope("write")
				.tokenSettings(tokenSettings())
				.build();
		return new InMemoryRegisteredClientRepository(registeredClient );
		
	}

	private TokenSettings tokenSettings() {
		return TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(30l)).build();
	}
	
	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> auth2TokenCustomizer() {
		return context -> {

			if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {

				Authentication principal = context.getPrincipal();

				Set<String> authorities = principal.getAuthorities().stream().map(GrantedAuthority::getAuthority)
						.collect(Collectors.toSet());

				context.getClaims().claim("roles", authorities);

			}
		};

	}

}

package ch.agilesolutions.jwt.security;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.kerberos.authentication.KerberosServiceRequestToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public class SpnegoSuccessHandler implements AuthenticationSuccessHandler {

	private static final String NEGOTIATE_PREFIX = "Negotiate ";

	private static final String WWW_AUTHENTICATE = "WWW-Authenticate";

	private String headerName = WWW_AUTHENTICATE;

	private String headerPrefix = NEGOTIATE_PREFIX;

	/**
	 * Sets the name of the header to set. By default this is
	 * 'WWW-Authenticate'.
	 *
	 * @param headerName
	 *            the www authenticate header name
	 */
	public void setHeaderName(String headerName) {
		this.headerName = headerName;
	}

	/**
	 * Sets the value of the prefix for the encoded response token value. By
	 * default this is 'Negotiate '.
	 *
	 * @param headerPrefix
	 *            the negotiate prefix
	 */
	public void setHeaderPrefix(String headerPrefix) {
		this.headerPrefix = headerPrefix;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		KerberosServiceRequestToken auth = (KerberosServiceRequestToken) authentication;
		if (auth.hasResponseToken()) {
			AuthenticationService.addToken(response, auth.getPrincipal().toString());
			response.addHeader(headerName, headerPrefix + auth.getEncodedResponseToken());
		}
	}
}

/*
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.streamsets.lib.security.http;

import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableSet;
import com.streamsets.datacollector.util.Configuration;
import com.streamsets.pipeline.api.impl.Utils;
import org.apache.commons.lang.StringUtils;
import org.eclipse.jetty.security.ServerAuthException;
import org.eclipse.jetty.server.Authentication;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class KeycloakSSOUserAuthenticator extends AbstractSSOAuthenticator {
  private static final Set<String> TOKEN_PARAM_SET =
      ImmutableSet.of(SSOConstants.USER_AUTH_TOKEN_PARAM, SSOConstants.REPEATED_REDIRECT_PARAM);

  private static final Logger LOG = LoggerFactory.getLogger(KeycloakSSOUserAuthenticator.class);
  private Configuration conf;

  public KeycloakSSOUserAuthenticator(
      String appContext,
      SSOService ssoService,
      Configuration configuration,
      String productName
  ) {
    super(ssoService);
    this.conf = configuration;

  }

  @Override
  protected Logger getLog() {
    return LOG;
  }

  @Override
  public Authentication validateRequest(
      ServletRequest request,
      ServletResponse response,
      boolean mandatory
  ) throws ServerAuthException {
    HttpServletRequest httpReq = (HttpServletRequest) request;
    HttpServletResponse httpRes = (HttpServletResponse) response;
    String authToken = getAuthTokenFromRequest(httpReq);

    LOG.info("Validiating Request in Keycloak SSO Authenticator");

    Authentication ret = null;

    String username = httpReq.getHeader("USER");
    if (StringUtils.isNotEmpty(username)) {
      LOG.info("Found header user: {}", username);
      SSOPrincipal sp = new SSOPrincipal() {
        @Override
        public String getTokenStr() {
          return username;
        }

        @Override
        public String getIssuerUrl() {
          return null;
        }

        @Override
        public long getExpires() {
          return 0;
        }

        @Override
        public String getPrincipalId() {
          return username;
        }

        @Override
        public String getPrincipalName() {
          return username;
        }

        @Override
        public String getOrganizationId() {
          return "test";
        }

        @Override
        public String getOrganizationName() {
          return "test";
        }

        @Override
        public String getEmail() {
          return username + "@example.com";
        }

        @Override
        public Set<String> getRoles() {
          Set<String> roles = new HashSet<>();
          roles.add("user");
          roles.add("admin");
          return roles;
        }

        @Override
        public Set<String> getGroups() {
          return Collections.singleton("all");
        }

        @Override
        public Map<String, String> getAttributes() {
          return null;
        }

        @Override
        public boolean isApp() {
          return false;
        }

        @Override
        public String getRequestIpAddress() {
          return null;
        }

        @Override
        public String getName() {
          return username;
        }
      };
      ret = new SSOAuthenticationUser(sp);
      return ret;
    }

    if (LOG.isTraceEnabled()) {
      LOG.trace("Request: {}", getRequestInfoForLogging(httpReq, SSOUtils.tokenForLog(authToken)));
    }

    if (isCORSOptionsRequest(httpReq)) {
      httpRes.setStatus(HttpServletResponse.SC_OK);
      httpRes.setHeader("Access-Control-Allow-Origin", conf.get(CORSConstants.HTTP_ACCESS_CONTROL_ALLOW_ORIGIN,
          CORSConstants.HTTP_ACCESS_CONTROL_ALLOW_ORIGIN_DEFAULT));
      httpRes.setHeader("Access-Control-Allow-Headers", conf.get(CORSConstants.HTTP_ACCESS_CONTROL_ALLOW_HEADERS,
          CORSConstants.HTTP_ACCESS_CONTROL_ALLOW_HEADERS_DEFAULT));
      httpRes.setHeader("Access-Control-Allow-Methods", conf.get(CORSConstants.HTTP_ACCESS_CONTROL_ALLOW_METHODS,
          CORSConstants.HTTP_ACCESS_CONTROL_ALLOW_METHODS_DEFAULT));
      return Authentication.SEND_SUCCESS;
    }

    if (!mandatory) {
      ret = Authentication.NOT_CHECKED;
    } else {
      if (authToken != null) {
        try {
          SSOPrincipal principal = getSsoService().validateUserToken(authToken);
          if (principal != null) {
            SSOAuthenticationUser user = new SSOAuthenticationUser(principal);
            if (isLogoutRequest(httpReq)) {
              if (LOG.isTraceEnabled()) {
                LOG.trace("Principal '{}' Logout", principal.getPrincipalId());
              }
              getSsoService().invalidateUserToken(authToken);
              ret = redirectToLogout(httpRes);
            } else {
              setAuthCookieIfNecessary(httpReq, httpRes, authToken, user.getSSOUserPrincipal().getExpires());
              if (isAuthTokenInQueryString(httpReq)) {
                if (LOG.isTraceEnabled()) {
                  LOG.trace(
                      "Redirection to self, principal '{}' request: {}",
                      principal.getPrincipalId(),
                      getRequestInfoForLogging(httpReq, SSOUtils.tokenForLog(authToken))
                  );
                }
                ret = redirectToSelf(httpReq, httpRes);
              } else {
                if (LOG.isDebugEnabled()) {
                  LOG.debug(
                      "Principal '{}' request: {}",
                      principal.getPrincipalId(),
                      getRequestInfoForLogging(httpReq, SSOUtils.tokenForLog(authToken))
                  );
                }
                ret = user;
              }
            }
          }
        } catch (ForbiddenException fex) {
          ret = returnUnauthorized(httpReq, httpRes, fex.getErrorInfo(), null, "Request: {}");
        }
      }
    }
    if (ret == null) {
      ret = returnUnauthorized(httpReq, httpRes, SSOUtils.tokenForLog(authToken), "Could not authenticate: {}");
    }
    return ret;
  }

  private boolean isCORSOptionsRequest(HttpServletRequest httpReq) {
    return "OPTIONS".equals(httpReq.getMethod());
  }

  boolean isLogoutRequest( HttpServletRequest httpReq) {
    String logoutPath = httpReq.getContextPath() + "/logout";
    return httpReq.getMethod().equals("GET") && httpReq.getRequestURI().equals(logoutPath);
  }

  Authentication redirectToLogout(HttpServletResponse httpRes) throws ServerAuthException {
    String urlToLogout = getSsoService().getLogoutUrl();
    try {
      LOG.debug("Redirecting to logout '{}'", urlToLogout);
      httpRes.sendRedirect(urlToLogout);
      return Authentication.SEND_SUCCESS;
    } catch (IOException ex) {
      throw new ServerAuthException(Utils.format("Could not redirect to '{}': {}", urlToLogout, ex.toString(), ex));
    }
  }

  void setAuthCookieIfNecessary(HttpServletRequest req, HttpServletResponse res, String authToken, long expiresMillis) {
    if (!authToken.equals(getAuthTokenFromCookie(req))) {
      res.addCookie(createAuthCookie(req, authToken, expiresMillis));
    }
  }

  Cookie createAuthCookie(HttpServletRequest httpReq, String authToken, long expiresMillis) {
    Cookie authCookie = new Cookie(getAuthCookieName(httpReq), authToken);
    authCookie.setPath("/");
    // if positive it is a persistent session, else a transient one and we don't have to set the cookie age
    if (expiresMillis > 0) {
      int secondsToLive = (int) ((expiresMillis - System.currentTimeMillis()) / 1000);
      authCookie.setMaxAge(secondsToLive);
    } else if (expiresMillis == 0) {
      // to delete the cookie
      authCookie.setMaxAge(0);
    }

    authCookie.setSecure(httpReq.isSecure());

    return authCookie;
  }

  String getAuthCookieName(HttpServletRequest httpReq) {
    return SSOConstants.AUTHENTICATION_COOKIE_PREFIX + httpReq.getServerPort();
  }

  Cookie getAuthCookie(HttpServletRequest httpReq) {
    Cookie[] cookies = httpReq.getCookies();
    if (cookies != null) {
      for (Cookie cookie : cookies) {
        if (cookie.getName().equals(getAuthCookieName(httpReq))) {
          return cookie;
        }
      }
    }
    return null;
  }

  String getAuthTokenFromCookie(HttpServletRequest httpReq) {
    Cookie cookie = getAuthCookie(httpReq);
    return (cookie == null) ? null : cookie.getValue();
  }

  boolean isAuthTokenInQueryString(HttpServletRequest httpReq) {
    return httpReq.getParameter(SSOConstants.USER_AUTH_TOKEN_PARAM) != null;
  }

  /*
   * Removes the token from request URL, redirects to the modified URL, returns the token as a header
   */
  Authentication redirectToSelf(HttpServletRequest httpReq, HttpServletResponse httpRes) throws ServerAuthException {
    String authToken = httpReq.getParameter(SSOConstants.USER_AUTH_TOKEN_PARAM);
    String urlWithoutToken = getRequestUrlWithoutToken(httpReq);
    httpRes.setHeader(SSOConstants.X_USER_AUTH_TOKEN, authToken);
    try {
      LOG.debug("Redirecting to self without token '{}'", urlWithoutToken);
      httpRes.sendRedirect(urlWithoutToken);
      return Authentication.SEND_CONTINUE;
    } catch (IOException ex) {
      throw new ServerAuthException(Utils.format("Could not redirect to '{}': {}", urlWithoutToken, ex.toString(), ex));
    }
  }

  String getRequestUrlWithoutToken(HttpServletRequest request) {
    return getRequestUrl(request, TOKEN_PARAM_SET).toString();
  }

  String getRequestUrl(HttpServletRequest request) {
    return getRequestUrl(request, Collections.emptySet()).toString();
  }

  String getAuthTokenFromRequest(HttpServletRequest httpReq) {
    String authToken = httpReq.getParameter(SSOConstants.USER_AUTH_TOKEN_PARAM);
    if (authToken == null) {
      authToken = httpReq.getHeader(SSOConstants.X_USER_AUTH_TOKEN);
      if (authToken == null) {
        authToken = getAuthTokenFromCookie(httpReq);
      }
    }
    return authToken;
  }

  StringBuffer getRequestUrl(HttpServletRequest request, Set<String> queryStringParamsToRemove) {
    StringBuffer requestUrl;

    requestUrl = new StringBuffer(request.getRequestURL());

    String qs = request.getQueryString();
    if (qs != null) {
      String qsSeparator = "?";
      for (String paramArg : Splitter.on("&").split(qs)) {
        String[] paramArgArr = paramArg.split("=", 2);
        if (!queryStringParamsToRemove.contains(paramArgArr[0])) {
          requestUrl.append(qsSeparator).append(paramArg);
          qsSeparator = "&";
        }
      }
    }
    return requestUrl;
  }
}

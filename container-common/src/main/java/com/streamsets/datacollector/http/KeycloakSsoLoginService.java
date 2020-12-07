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
package com.streamsets.datacollector.http;

import com.streamsets.datacollector.util.Configuration;
import com.streamsets.lib.security.http.RegistrationResponseDelegate;
import com.streamsets.lib.security.http.SSOPrincipal;
import com.streamsets.lib.security.http.SSOService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

public class KeycloakSsoLoginService implements SSOService {
  private static final Logger LOG = LoggerFactory.getLogger(KeycloakSsoLoginService.class);

  @Override
  public void setDelegateTo(SSOService ssoService) {
    LOG.info("Set delegate to ssoService: {}", ssoService);
  }

  @Override
  public SSOService getDelegateTo() {
    LOG.info("Get DelegateTo");
    return null;
  }

  @Override
  public void setConfiguration(Configuration configuration) {
    LOG.info("Set Configuration");
  }

  @Override
  public void register(Map<String, String> attributes) {
    LOG.info("register attributes");

  }

  @Override
  public String createRedirectToLoginUrl(String requestUrl, boolean duplicateRedirect) {
    LOG.info("createRedirectToLoginUrl: {}", requestUrl);
    return null;
  }

  @Override
  public String getLogoutUrl() {
    LOG.info("getLogoutUrl");
    return null;
  }

  @Override
  public SSOPrincipal validateUserToken(String authToken) {
    LOG.info("Validating user token: {}", authToken);
    return null;
  }

  @Override
  public boolean invalidateUserToken(String authToken) {
    LOG.info("Invalida user token: {}", authToken);
    return false;
  }

  @Override
  public SSOPrincipal validateAppToken(String authToken, String componentId) {
    LOG.info("Validating app token: {}", authToken);
    return null;
  }

  @Override
  public boolean invalidateAppToken(String authToken) {
    LOG.info("Invalidate token: {}", authToken);
    return false;
  }

  @Override
  public void clearCaches() {
    LOG.info("Clear caches");
  }

  @Override
  public void setRegistrationResponseDelegate(RegistrationResponseDelegate delegate) {
    LOG.info("setRegistrationResponseDelegate");
  }
}

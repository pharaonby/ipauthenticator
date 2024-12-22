package com.firebird.keycloak;

import org.keycloak.Config;
import org.keycloak.authentication.*;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.*;

/**
 * @author Sergei Klimovich
 */
public class IpAddressAuthenticatorFactory implements AuthenticatorFactory {

    private static final String PROVIDER_ID = "ip-address-authenticator";
    private static final IpAddressAuthenticator SINGLETON = new IpAddressAuthenticator();
    static final String ALLOWED_IP_ADDRESS_CONFIG_NAME = "allowed_ip_address";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "IP Address Authenticator";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return List.of(AuthenticationExecutionModel.Requirement.REQUIRED)
            .toArray(new AuthenticationExecutionModel.Requirement[0]);
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Executes the flow only if the client IP matches any of the configured IP addresses. Supports multiple IPs separated by commas.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty name = new ProviderConfigProperty();
        name.setType(ProviderConfigProperty.STRING_TYPE);
        name.setName(ALLOWED_IP_ADDRESS_CONFIG_NAME);
        name.setLabel("Allowed IP Address which does not next auth steps");
        name.setHelpText("Supports multiple IPs separated by commas.");
        return Collections.singletonList(name);
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope scope) {
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
    }

    @Override
    public void close() {
    }
}

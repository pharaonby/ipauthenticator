package com.firebird.keycloak;

import org.jboss.logging.Logger;
import org.keycloak.authentication.*;
import org.keycloak.models.*;

import java.util.Arrays;

/**
 * @author Sergei Klimovich
 */
public class IpAddressAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(IpAddressAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        //allowedIPAddress - берем все разрешенный айпи из конфига аутентификатора
        String allowedIPAddress = context.getAuthenticatorConfig().getConfig()
            .get(IpAddressAuthenticatorFactory.ALLOWED_IP_ADDRESS_CONFIG_NAME);
        if (allowedIPAddress == null || allowedIPAddress.isEmpty()) {
            logger.warn("###### Allowed IP Address configuration is missing.");
            context.attempted();
            return;
        }

        //clientIp - айпи клиента
        String clientIp = context.getConnection().getRemoteAddr();

        //isAllowed - переменная, для передачи в condition
        boolean isAllowed = isIpAllowed(clientIp, allowedIPAddress);
        context.getAuthenticationSession().setAuthNote("isAllowed", String.valueOf(isAllowed));
        logger.infof("###### IS_ALLOWED: %s", isAllowed);
        if (isAllowed) {
            logger.infof("###### Authentication successful for IP: %s", clientIp);
            UserModel user = getSingleUser(context);
            logger.info("###### USER: " + (user != null ? user.getUsername() : "null"));
            if (user != null) {
                context.setUser(user);
                logger.info("###### Successfully transitioned to the resource directly.");
                context.success();
            } else {
                logger.warn("###### No user found.");
                context.attempted();
            }
        } else {
            logger.infof("###### Authentication for IP: %s is not allowed.", clientIp);
            context.attempted();
            logger.info("###### STATUS2: " + context.getStatus().name());
            logger.infof("###### FINISH222");
        }
        logger.info("###### STATUS3: " + context.getStatus().name());
    }

    private UserModel getSingleUser(AuthenticationFlowContext context) {
        RealmModel realm = context.getRealm();
        return context.getSession().users().getUserByUsername(realm, "admin");
    }

    private boolean isIpAllowed(String clientIp, String allowedIPs) {
        logger.info("###### Allowed IPS: " + allowedIPs);
        return Arrays.stream(allowedIPs.split(","))
            .map(String::trim)
            .anyMatch(ip -> ip.equals(clientIp));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}

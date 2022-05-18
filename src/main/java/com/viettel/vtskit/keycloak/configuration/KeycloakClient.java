package com.viettel.vtskit.keycloak.configuration;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

import static org.keycloak.OAuth2Constants.CLIENT_CREDENTIALS;


@Component
public class KeycloakClient {
    @Autowired
    KeycloakProperties keycloakProperties;

    @Bean
    public Keycloak keycloakAdminClient(){
        return KeycloakBuilder.builder()
                .serverUrl(keycloakProperties.getAuthServerUrl())
                .realm("master")
                .clientId("admin-cli")
                .username("admin")
                .password("admin")
                .build();
    }
    public AuthzClient authzClient(){
        Map clientCredentials = new HashMap<String, Object>();
        clientCredentials.put("secret", keycloakProperties.getClientKeyPassword());
        clientCredentials.put("grant_type", "password");
        Configuration configuration =
                new Configuration(keycloakProperties.getAuthServerUrl(), keycloakProperties.getRealm(),
                        keycloakProperties.getResource(), clientCredentials, null);
        return AuthzClient.create(configuration);
    }

    @Bean
    public RealmResource realmResource(Keycloak keycloak) {
        return keycloak.realm(keycloakProperties.getRealm());
    }

    public String getTokenUrl(){
        return keycloakProperties.getAuthServerUrl()+"/realms/"+keycloakProperties.getRealm()+"/protocol/openid-connect/token";
    }

    public String logoutUrl(){
        return keycloakProperties.getAuthServerUrl()+"/realms/"+keycloakProperties.getRealm()+"/protocol/openid-connect/logout";
    }

    public String getUserInfoUrl(){
        return keycloakProperties.getAuthServerUrl()+"/realms/"+keycloakProperties.getRealm()+"/protocol/openid-connect/userinfo";
    }
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
    public MultiValueMap<String, String> getClient(){
        MultiValueMap map =  new LinkedMultiValueMap<String, String>();
        map.set("client_id", keycloakProperties.getResource());
        map.set("client_secret", keycloakProperties.getClientKeyPassword());
        return map;
    }
}

package com.viettel.vtskit.keycloak.configuration;

import org.keycloak.adapters.springboot.KeycloakSpringBootProperties;

import javax.annotation.PostConstruct;


public class KeycloakProperties extends KeycloakSpringBootProperties {

    /**
     * Validate properties at here if necessary
     */
    private void validateProperties(){
    }

    @PostConstruct
    void init(){
        validateProperties();
    }

}

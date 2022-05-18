package com.viettel.vtskit.keycloak;

import com.viettel.vtskit.keycloak.configuration.ConstantConfiguration;
import com.viettel.vtskit.keycloak.configuration.KeycloakClient;
import com.viettel.vtskit.keycloak.configuration.KeycloakProperties;
import com.viettel.vtskit.keycloak.dto.UserDTO;
import org.json.JSONException;
import org.json.JSONObject;
import org.keycloak.admin.client.CreatedResponseUtil;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;

import javax.ws.rs.core.Response;

import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

public class KeycloakService{
    @Autowired
    private KeycloakProperties keycloakProperties;
    @Autowired
    private KeycloakClient keycloakClient;
    @Autowired
    private Keycloak keycloakAdminClient;
    @Autowired
    private RealmResource keycloakRealmResource;
    @Autowired
    private RestTemplate restTemplate;

    public AccessTokenResponse authenticate(UserDTO userDTO) {

               Assert.notNull(userDTO.getUsername(), "Username is null");
               Assert.notNull(userDTO.getPassword(), "Password is null");

               AuthzClient authzClient = keycloakClient.authzClient();
               AccessTokenResponse authResponse = authzClient.obtainAccessToken(userDTO.getUsername(), userDTO.getPassword());
               return authResponse;

    }

    public AccessTokenResponse refreshToken(String refreshToken) {
            Assert.notNull(refreshToken, "Refresh token is null");

            MultiValueMap refreshTokenRequest = keycloakClient.getClient();
            refreshTokenRequest.set("refresh_token", refreshToken);
            refreshTokenRequest.set("grant_type", "refresh_token");

            HttpHeaders headers = new HttpHeaders();
            headers.set(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
            headers.set(HttpHeaders.ACCEPT,MediaType.APPLICATION_JSON_VALUE);
            HttpEntity request = new HttpEntity<>(refreshTokenRequest,headers);

            ResponseEntity<AccessTokenResponse> authResponse =  restTemplate.postForEntity(keycloakClient.getTokenUrl(),request, AccessTokenResponse.class);

            return authResponse.getBody();
    }
    private ResponseEntity logoutUserSession(MultiValueMap<String, String> requestParams){
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(requestParams, headers);
        ResponseEntity response=restTemplate.postForEntity(keycloakClient.logoutUrl(),request, Object.class);
        return response;
    }

    public HttpStatus logout(String refreshToken){
        //        http://localhost:8080/realms/keycloak-demo/protocol/openid-connect/logout
        try{
            Assert.notNull(refreshToken, "Refresh token is null");
            MultiValueMap<String, String> requestParams = new LinkedMultiValueMap<>();
            requestParams.add("client_id", keycloakProperties.getResource());
            requestParams.add("client_secret", keycloakProperties.getClientKeyPassword());
            requestParams.add("refresh_token", refreshToken);

            return logoutUserSession(requestParams).getStatusCode();
        } catch (Exception e) {
            throw e;
        }
    }

    public JSONObject getUserInfo(String token) throws JSONException {
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Authorization", token);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(null, headers);
        String response =restTemplate.postForObject(keycloakClient.getUserInfoUrl(), request, String.class);
        JSONObject jsonObject=new JSONObject(response);
        return jsonObject;
    }

    public int createUser(UserDTO userDTO){
        keycloakAdminClient.tokenManager().getAccessToken();
        UserRepresentation user = new UserRepresentation();
        user.setEnabled(true);
        user.setUsername(userDTO.getUsername());
        user.setFirstName(userDTO.getFirstname());
        user.setLastName(userDTO.getLastname());
        user.setEmail(userDTO.getEmail());
        UsersResource usersResource = keycloakRealmResource.users();

        Response response = usersResource.create(user);

        userDTO.setStatusCode(response.getStatus());
        userDTO.setStatus(response.getStatusInfo().toString());
        if (response.getStatus() == 201) {
            String userId = CreatedResponseUtil.getCreatedId(response);
            // create password credential
            CredentialRepresentation passwordCred = new CredentialRepresentation();
            passwordCred.setTemporary(false);
            passwordCred.setType(CredentialRepresentation.PASSWORD);
            passwordCred.setValue(userDTO.getPassword());

            UserResource userResource = usersResource.get(userId);
            // Set roles
            userResource.roles().realmLevel();
            // Set password credential
            userResource.resetPassword(passwordCred);
            // Get realm role
//            RoleRepresentation realmRoleUser = keycloakRealmResource.roles().get("user").toRepresentation();
//            // Assign realm role student to user
//            userResource.roles().realmLevel().add(Arrays.asList(realmRoleUser));

        }
        return response.getStatus();
    }

    public int deleteUser(String accessToken) throws JSONException {
        UsersResource usersResource = keycloakRealmResource.users();
        String userId= getUserInfo(accessToken).get("sub").toString();
        Response response =usersResource.delete(userId);
        return response.getStatus();
    }

    public void updateUser(String accessToken, UserDTO userDTO) throws JSONException {
        UsersResource usersResource = keycloakRealmResource.users();
        UserRepresentation userRepresentation=new UserRepresentation();
        userRepresentation.setUsername(userDTO.getUsername());
        userRepresentation.setFirstName(userDTO.getFirstname());
        userRepresentation.setLastName(userDTO.getLastname());
        userRepresentation.setEmail(userDTO.getEmail());
        String userId= getUserInfo(accessToken).get("sub").toString();
        UserResource userResource=usersResource.get(userId);
        userResource.update(userRepresentation);
    }
    public void changePassword(String accessToken, String password){
        CredentialRepresentation passwordCred = new CredentialRepresentation();
        passwordCred.setTemporary(false);
        passwordCred.setType(CredentialRepresentation.PASSWORD);
        passwordCred.setValue(password);
        UsersResource usersResource = keycloakRealmResource.users();
        String userId= getUserInfo(accessToken).get("sub").toString();
        UserResource userResource = usersResource.get(userId);
        userResource.resetPassword(passwordCred);
    }
    public String exampleFunction(String name){
        return String.format(ConstantConfiguration.GREETING_MESSAGE, name);
    }



}

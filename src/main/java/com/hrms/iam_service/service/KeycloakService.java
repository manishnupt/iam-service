package com.hrms.iam_service.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.impl.BeanPropertyMap;
import com.hrms.iam_service.dto.KCAdminAccessTokenRequest;
import com.hrms.iam_service.dto.KCOnboardUserRequest;
import com.hrms.iam_service.dto.KCRealmAccessTokenRequest;
import com.hrms.iam_service.dto.RealmRoleDetails;
import com.hrms.iam_service.response.KCCreateClientResponse;
import com.hrms.iam_service.response.KCRealmAccessTokenResponse;
import com.hrms.iam_service.response.KCTenantInfoResponse;
import com.hrms.iam_service.response.KeycloakConfigResponse;
import com.hrms.iam_service.utility.Constants;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
@Log4j2
public class KeycloakService {

    @Autowired
    RestTemplate restTemplate;


    @Value("${keycloak.endpoints.redirect-uri}")
    private String redirectUri;

    @Value("${keycloak.endpoint}")
    private String keycloakEndpoint;

    @Value("${tenant-management.endpoint}")
    private String tenantManagementEndpoint;

    private static final String TOKEN_URL = "realms/master/protocol/openid-connect/token";
    private static final String REALM_URL="admin/realms";
    private static final String CLIENT_CREATE_URL="admin/realms/{realm}/clients";
    private static final String ROLE_CREATE_URL="admin/realms/{realm}/roles";
    private static final String CREATE_GROUP="admin/realms/{realm}/groups";
    private static final String GET_REALM_ROLES="admin/realms/{realm}/roles";
    private static final String ASSIGN_GROUP_ROLES= "admin/realms/{realm}/groups/{groupId}/role-mappings/realm";
    private static final String CREATE_USER="admin/realms/{realm}/users";
    private static final String GET_CLIENTS="admin/realms/{realm}/clients";
    private static final String ASSIGN_USER_ROLES="admin/realms/{realm}/users/{user}/role-mappings/clients/{client}";
    private static final String GET_CLIENT_ROLES="admin/realms/{realm}/clients/{client}/roles";
    private static final String ASSIGN_GROUP_TO_USER="admin/realms/{realm}/users/{userId}/groups/{groupId}";
    private static final String VALIDATE_REALM="admin/realms/{realm}";
    private static final String REALM_TOKEN_URL = "realms/{realm}/protocol/openid-connect/token";

    private static final String TENANT_KC_CONFIG="/api/v1/tenants/auth-config/{realm}";

    private static final String UNASSIGN_GROUP_FROM_USER = "admin/realms/{realm}/users/{userId}/groups/{groupId}";





    public String getAdminAccessToken(KCAdminAccessTokenRequest request) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);


        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("client_id", request.getClientId());
        //requestBody.add("client_secret", request.getClientSecret());
        requestBody.add("username", request.getUsername());
        requestBody.add("password", request.getPassword());
        requestBody.add("grant_type", "password");
        log.info("this is a request to generate the admin token :{}",requestBody);

        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(requestBody, headers);
        try {
            log.info("uri:{} ,request:{}",keycloakEndpoint + TOKEN_URL,requestEntity);
            ResponseEntity<Map> response = restTemplate.exchange(keycloakEndpoint + TOKEN_URL, HttpMethod.POST, requestEntity, Map.class);
            if (response.getStatusCode() == HttpStatus.OK) {
                System.out.println("Access Token: " + response.getBody().get("access_token"));
                return response.getBody().get("access_token").toString();
            } else {
                throw new RuntimeException("error");
                //System.out.println("Failed to fetch token. Status: " + response.getStatusCode());
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    public String createRealm(String token, String realmName) {
        validateNotNull(token, "token");
        validateNotNull(realmName, "realmName");
        //String url = keycloakBaseUrl + keycloakUrls.getRealms();
        String requestBody = String.format(
                "{"
                        + "\"realm\":\"%s\","
                        + "\"enabled\":true"
                        + "}",
                realmName);
        HttpHeaders headers = createHeaders(token);

        // Create the request entity
        HttpEntity<String> requestEntity = new HttpEntity<>(requestBody, headers);

        try {
            // Call the Keycloak API
            ResponseEntity<String> response = restTemplate.exchange(keycloakEndpoint+REALM_URL, HttpMethod.POST, requestEntity, String.class);
            return response.getBody();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create realm: " + realmName, e);
        }
    }
    private void validateNotNull(Object value, String message) {
        if (value == null) {
            throw new IllegalArgumentException(message);
        }
    }

    private HttpHeaders createHeaders(String adminToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        // Ensure 'Bearer' is not duplicated
        if (!adminToken.startsWith("Bearer ")) {
            adminToken = "Bearer " + adminToken;
        }
        headers.set("Authorization", adminToken);
        return headers;
    }

    public KCCreateClientResponse createClient(String adminToken, String realm) {
        validateNotNull(adminToken, "adminToken");
        validateNotNull(realm, "realmName");

        String url = keycloakEndpoint+CLIENT_CREATE_URL.replace("{realm}", realm);

        // Create client details payload
        Map<String, Object> clientDetailsReq = new HashMap<>();
        clientDetailsReq.put("clientId", Constants.DEFAULT_KEYCLOAK_CLIENT);
        clientDetailsReq.put("name", Constants.DEFAULT_KEYCLOAK_CLIENT);
        clientDetailsReq.put("enabled", Boolean.TRUE);
        clientDetailsReq.put("protocol", Constants.DEFAULT_KEYCLOAK_PROTOCOL);
        clientDetailsReq.put("publicClient", Boolean.FALSE);

        // Add Redirect URIs (must be a List)
        clientDetailsReq.put("redirectUris", Arrays.asList(redirectUri.replace("{realm}", realm)));
        // Add Attributes Map (post.logout.redirect.uris must be a space-separated
        // string)
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("post.logout.redirect.uris", redirectUri.replace("{realm}", realm));
        clientDetailsReq.put("attributes", attributes);

        HttpHeaders headers = createHeaders(adminToken);
        HttpEntity<Map<String, Object>> request = new HttpEntity<>(clientDetailsReq, headers);

        try {
            // Send POST request
            ResponseEntity<String> response = restTemplate.postForEntity(url, request, String.class);
            if (response.getStatusCode() == HttpStatus.CREATED) {
                return getClientDetails(adminToken, realm, response.getHeaders().get("location").get(0));
            } else {
                throw new RuntimeException("Error in creating client");
            }
        } catch (Exception e) {
            throw new RuntimeException("Error creating client in Keycloak: " + e.getMessage(), e);
        }
    }
    public KCCreateClientResponse getClientDetails(String adminToken, String realmName, String location) {

        validateNotNull(adminToken, "adminToken");
        validateNotNull(realmName, "realmName");
        validateNotNull(location, "clientId");

        HttpHeaders headers = createHeaders(adminToken);
        HttpEntity<Void> request = new HttpEntity<>(headers);

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    location,
                    HttpMethod.GET,
                    request,
                    new ParameterizedTypeReference<>() {
                    });
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                ObjectMapper objectMapper = new ObjectMapper(); // Preferably use a pre-configured instance
                Map<String, Object> responseBody = objectMapper.readValue(response.getBody(), new TypeReference<>() {
                });
                return KCCreateClientResponse.builder()
                        .name(responseBody.get("name").toString())
                        .id(responseBody.get("id").toString())
                        .clientId(responseBody.get("clientId").toString())
                        .clientSecret(responseBody.get("secret").toString())
                        .build();
            } else {
                throw new RuntimeException("Client details not found for the given URL: " + location);
            }
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to parse client details response", e);
        }
    }

    public  void createRoles(String token,String realmName,String[] roles) {

        for (String roleName : roles) {
            Map<String, Object> rolePayload = new HashMap<>();
            rolePayload.put("name", roleName);
            rolePayload.put("description", "");  // Optional
            rolePayload.put("attributes", new HashMap<>()); // Empty attributes map
            HttpHeaders headers = createHeaders(token);
            String url = keycloakEndpoint+ROLE_CREATE_URL.replace("{realm}", realmName);

            HttpEntity<Map<String, Object>> requestEntity = new HttpEntity<>(rolePayload, headers);

            ResponseEntity<String> response = restTemplate.exchange(
                    url, HttpMethod.POST, requestEntity, String.class
            );
            if (response.getStatusCode().is2xxSuccessful()) {
                System.out.println("Role created: " + roleName);
            } else {
                System.out.println("Failed to create role: " + roleName + " - " + response.getBody());
            }
        }
    }


    public String createGroup(String token,String groupName, String realm) {
        validateNotNull(realm,"realm");
        validateNotNull(groupName,"groupName");
        String url = keycloakEndpoint+CREATE_GROUP.replace("{realm}", realm);

        Map<String, Object> groupReq = new HashMap<>();
        groupReq.put("name", groupName);
        HttpHeaders headers = createHeaders(token);
        HttpEntity<Map<String, Object>> request = new HttpEntity<>(groupReq, headers);
        try {
            // Send POST request
            ResponseEntity<String> response = restTemplate.postForEntity(url, request, String.class);
            if (response.getStatusCode() == HttpStatus.CREATED) {
                System.out.println("hello");
                return extractIdFromPath(Constants.EXTRACT_GROUP_ID_REGEX,(Objects.requireNonNull(response.getHeaders().get("location"))).get(0));
            } else {
                throw new RuntimeException("Error in creating client");
            }
        } catch (Exception e) {
            throw new RuntimeException("Error creating client in Keycloak: " + e.getMessage(), e);
        }
    }

    public String extractIdFromPath(String regex,String url) {
        // Define the regex pattern to match the user ID (UUID format)
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(url);

        // If the pattern matches, extract the user ID
        if (matcher.find()) {
            return matcher.group(1);
        } else {
            throw new IllegalArgumentException("Invalid URL or user ID not found.");
        }
    }

    public void assignRolesToGroup(String token, String groupId, List<String> roles, String realmName) {
        String url = keycloakEndpoint+ASSIGN_GROUP_ROLES.replace("{realm}", realmName).replace("{groupId}",groupId);
        HttpHeaders headers = createHeaders(token);
        List<RealmRoleDetails> allRealmRoles = getAllRealmRoles(token, realmName).stream().filter(role->roles.contains(role.getName())).toList();
        HttpEntity<List<RealmRoleDetails>> requestEntity = new HttpEntity<>(allRealmRoles, headers);
        try {
            restTemplate.exchange(url, HttpMethod.POST, requestEntity, String.class);
        }catch (Exception ex){
            throw new RuntimeException("Error fetching roles from realm in keycloak " );
        }
    }

    public List<RealmRoleDetails> getAllRealmRoles(String token, String realmName){
        String url = keycloakEndpoint+GET_REALM_ROLES.replace("{realm}", realmName);
        HttpHeaders headers = createHeaders(token);
        HttpEntity<String> requestEntity = new HttpEntity<>(headers);
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, requestEntity, String.class);
        if (response.getStatusCode() == HttpStatus.OK) {
            return parseRoles(response.getBody());
        } else {
            throw new RuntimeException("Error fetching roles from realm in keycloak " );
        }
    }
    private List<RealmRoleDetails> parseRoles(String responseBody) {
        List<RealmRoleDetails> roleDetailsList = new ArrayList<>();
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode rootNode = objectMapper.readTree(responseBody);
            for (JsonNode node : rootNode) {
                RealmRoleDetails roleDetails = new RealmRoleDetails();
                roleDetails.setId(node.get("id").asText());
                roleDetails.setName(node.get("name").asText());
                roleDetails.setComposite(node.get("composite").asBoolean());
                roleDetails.setContainerId(node.get("containerId").asText());
                roleDetailsList.add(roleDetails);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return roleDetailsList;
    }


    public String createUser(String token, KCOnboardUserRequest userRequest, String realmName) {
        validateNotNull(userRequest, "user provided");
        String url = keycloakEndpoint+CREATE_USER.replace("{realm}", realmName);
        HttpHeaders headers = createHeaders(token);
        HttpEntity<KCOnboardUserRequest> request = new HttpEntity<>(userRequest, headers);
        log.info("Request log:{}",userRequest);
        ResponseEntity<Void> response = restTemplate.exchange(url, HttpMethod.POST, request, Void.class);
        if (response.getStatusCode() == HttpStatus.CREATED) {
            return extractIdFromPath(Constants.EXTRACT_USER_ID_REGEX,response.getHeaders().getLocation().toString());
        } else {
            throw new RuntimeException("Failed to create user: " + response.getStatusCode() );
        }
    }

    public void grantSuperAdminAccess(String token, String realmName, String userId,String groupId) {
        try {
            List<Map> clients = getClients(token, realmName);

            for (Map client : clients) {
                if ("realm-management".equals(client.get("clientId"))) {
                    String clientId = (String) client.get("id");

                    List<Map<String, Object>> roles = getClientRoles(token, realmName, clientId);

                    String manageUsersRoleId = null;
                    String manageClientsRoleId = null;

                    for (Map<String, Object> role : roles) {
                        String roleName = (String) role.get("name");
                        if ("manage-users".equals(roleName)) {
                            manageUsersRoleId = (String) role.get("id");
                        }
                        if ("manage-clients".equals(roleName)) {
                            manageClientsRoleId = (String) role.get("id");
                        }
                    }

                    if (manageUsersRoleId != null && manageClientsRoleId != null) {
                        List<Map<String, Object>> roleAssignments = List.of(
                                Map.of("id", manageUsersRoleId, "name", "manage-users"),
                                Map.of("id", manageClientsRoleId, "name", "manage-clients"));

                        assignClientRolesToUser(token, realmName, userId, clientId, roleAssignments);
                        assignUserToGroup(token, realmName, userId, groupId);
                        return; // Successfully assigned roles
                    } else {
                        throw new RuntimeException("Required roles ('manage-users' ) not found for client.");
                    }
                }
            }

            throw new RuntimeException("Client 'realm-management' not found in the realm.");
        } catch (Exception e) {
            throw new RuntimeException("Error while granting admin access: " + e.getMessage(), e);
        }
    }

    public List<Map> getClients(String token, String realmName) {
        String getClientsUrl = keycloakEndpoint+GET_CLIENTS.replace("{realm}", realmName);
        HttpHeaders headers = createHeaders(token);

        ResponseEntity<Map[]> clientsResponse = restTemplate.exchange(
                getClientsUrl, HttpMethod.GET, new HttpEntity<>(headers), Map[].class);

        if (clientsResponse.getStatusCode() == HttpStatus.OK) {
            return Arrays.asList(clientsResponse.getBody());
        } else {
            throw new RuntimeException("Failed to fetch clients for realm: " + clientsResponse.getStatusCode());
        }
    }

    public void assignClientRolesToUser(String token, String realmName, String userId, String clientId,
                                  List<Map<String, Object>> roles) {
        String assignRoleUrl = keycloakEndpoint+ASSIGN_USER_ROLES.replace("{realm}", realmName)
                .replace("{user}", userId).replace("{client}", clientId);
        HttpHeaders headers = createHeaders(token);

        HttpEntity<List<Map<String, Object>>> entity = new HttpEntity<>(roles, headers);

        ResponseEntity<Void> roleResponse = restTemplate.exchange(assignRoleUrl, HttpMethod.POST, entity, Void.class);

        if (roleResponse.getStatusCode() != HttpStatus.NO_CONTENT) {
            throw new RuntimeException("Failed to assign roles to the user: " + roleResponse.getStatusCode());
        }
    }
    public List<Map<String, Object>> getClientRoles(String token, String realmName, String clientId) {
        String allClientRolesUrl = keycloakEndpoint+GET_CLIENT_ROLES.replace("{realm}", realmName)
                .replace("{client}", clientId);
        HttpHeaders headers = createHeaders(token);

        ResponseEntity<Map[]> rolesResponse = restTemplate.exchange(
                allClientRolesUrl, HttpMethod.GET, new HttpEntity<>(headers), Map[].class);

        if (rolesResponse.getStatusCode() == HttpStatus.OK) {
            return Arrays.asList(rolesResponse.getBody());
        } else {
            throw new RuntimeException("Failed to fetch roles for client: " + rolesResponse.getStatusCode());
        }
    }

    public void assignUserToGroup(String token, String realm, String userId, String groupId) {
        try {
            HttpHeaders headers = createHeaders(token);
            HttpEntity<String> request = new HttpEntity<>(headers);
            String assignGroupUrl = keycloakEndpoint+ASSIGN_GROUP_TO_USER.replace("{realm}", realm)
                                .replace("{userId}", userId).replace("{groupId}", groupId);
            restTemplate.exchange(assignGroupUrl, HttpMethod.PUT, request, Void.class);
        } catch (Exception e) {
            throw new RuntimeException("Error while assigning user to group: " + e.getMessage(), e);
        }
    }


    public KCTenantInfoResponse validateTenant(String token, @NotBlank String tenantName) {
        HttpHeaders headers = createHeaders(token);
        String url = keycloakEndpoint+VALIDATE_REALM.replace("{realm}", tenantName);
        HttpEntity<String> requestEntity = new HttpEntity<>(headers);
        try {
            restTemplate.exchange(url, HttpMethod.GET, requestEntity, String.class);
            String redirectURI = String.format(Constants.TENANT_REDIRECT_URI,keycloakEndpoint ,tenantName,
                    Constants.TENANT_CLIENT_ID, redirectUri.replace("{realm}",tenantName));

            KCTenantInfoResponse response = KCTenantInfoResponse.builder()
                   // .id(tenant.getId())
                    .realm(tenantName)
                    .redirectURI(redirectURI)
                    .build();
            return response;
        }
        catch(Exception e){
            throw new InputMismatchException("No tenant found with this name");
        }
    }

    public KCRealmAccessTokenResponse validateAuthCode(@Valid KCRealmAccessTokenRequest request) {
        KeycloakConfigResponse tenantKeyCloakConfig = getTenantKeyCloakConfig(request.getTenantName(), request.getAuthCode());
        return getRealmAccessToken(request, tenantKeyCloakConfig);
    }

    private KCRealmAccessTokenResponse getRealmAccessToken(@Valid KCRealmAccessTokenRequest req, KeycloakConfigResponse tenantKeyCloakConfig) {
        String realm = req.getTenantName();
        String url = keycloakEndpoint+REALM_TOKEN_URL.replace("{realm}", realm);

        // Prepare form params
        MultiValueMap<String, String> formParams = new LinkedMultiValueMap<>();
        formParams.add("grant_type", "authorization_code");
        formParams.add("code", req.getAuthCode());
        formParams.add("redirect_uri", redirectUri.replace("{realm}",realm));
        formParams.add("client_id", tenantKeyCloakConfig.getData().getClientId());
        formParams.add("client_secret", tenantKeyCloakConfig.getData().getClientSecret());

        // Prepare headers
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // Combine headers and body
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(formParams, headers);

        // Send request
        ResponseEntity<KCRealmAccessTokenResponse> response = restTemplate.postForEntity(
                url,
                request,
                KCRealmAccessTokenResponse.class
        );

        return response.getBody();
    }

    private KeycloakConfigResponse getTenantKeyCloakConfig(String tenantName, String authCode) {
        String url = tenantManagementEndpoint+TENANT_KC_CONFIG.replace("{realm}", tenantName);
        ResponseEntity<KeycloakConfigResponse> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                null,
                new ParameterizedTypeReference<>() {},
                tenantName
        );

        return response.getBody();

    }

    public void logoutUser(String token, String realm) {
        KeycloakConfigResponse tenantKeyCloakConfig = getTenantKeyCloakConfig(realm, null);
        String logoutUrl = keycloakEndpoint + "realms/" + realm + "/protocol/openid-connect/logout";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", tenantKeyCloakConfig.getData().getClientId());
        form.add("client_secret", tenantKeyCloakConfig.getData().getClientSecret());
        form.add("refresh_token", token); // refresh token you currently store

        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(form, headers);

        ResponseEntity<String> kcResponse = restTemplate.postForEntity(logoutUrl, entity, String.class);
        log.info("Keycloak logout response: {}", kcResponse.getStatusCode());
    }

    public void removeGroupAccess(String token, String realmName, String userId, String groupId) {
        try {
            HttpHeaders headers = createHeaders(token);
            HttpEntity<String> request = new HttpEntity<>(headers);
            String removeGroupUrl = keycloakEndpoint+UNASSIGN_GROUP_FROM_USER.replace("{realm}", realmName)
                    .replace("{userId}", userId).replace("{groupId}", groupId);
            restTemplate.exchange(removeGroupUrl, HttpMethod.DELETE, request, Void.class);
        } catch (Exception e) {
            throw new RuntimeException("Error while removing user from group: " + e.getMessage(), e);
        }
    }

    public void removeRolesFromGroup(String token, String groupId, List<UUID> roles, String realmName) {
        String url = keycloakEndpoint+ASSIGN_GROUP_ROLES.replace("{realm}", realmName).replace("{groupId}",groupId);
        HttpHeaders headers = createHeaders(token);
        List<RealmRoleDetails> allRealmRoles =
                getAllRealmRoles(token, realmName).stream()
                        .filter(role -> roles.contains(UUID.fromString(role.getId())))
                        .toList();
        HttpEntity<List<RealmRoleDetails>> requestEntity = new HttpEntity<>(allRealmRoles, headers);
        try {
            restTemplate.exchange(url, HttpMethod.DELETE, requestEntity, String.class);
        }catch (Exception ex){
            throw new RuntimeException("Error fetching roles from realm in keycloak " );
        }
    }
}

package com.hrms.iam_service.controller;

import com.hrms.iam_service.dto.*;
import com.hrms.iam_service.response.HttpDataResponse;
import com.hrms.iam_service.response.KCCreateClientResponse;
import com.hrms.iam_service.response.KCRealmAccessTokenResponse;
import com.hrms.iam_service.response.KCTenantInfoResponse;
import com.hrms.iam_service.service.KeycloakService;
import com.hrms.iam_service.utility.Constants;
import com.hrms.iam_service.utility.HttpDataResponseUtil;
import jakarta.validation.Valid;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Value;


import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

@RestController
@RequestMapping("/iamcontroller")
@CrossOrigin(origins="*")
@Log4j2
public class IamController {


    @Autowired
    private KeycloakService keyCloakService;

    @Autowired
    private HttpDataResponseUtil httpDataResponseUtil;
    
    @Value("${keycloak.endpoint}")
    private String keycloakBaseUrl;


    @PostMapping("/keycloak-token")
    public ResponseEntity<?> getKeycloakToken(@RequestBody KCAdminAccessTokenRequest request) {
        log.info("Keycloak admin token request received for client: [{}]", request.getClientId());
        try {
            String token = keyCloakService.getAdminAccessToken(request);
            Map<String, String> tokenResponse = new HashMap<>();
            tokenResponse.put("token", token);
            log.info("Keycloak admin token generated successfully for client: [{}]", request.getClientId());
            return ResponseEntity.status(HttpStatus.CREATED).body(tokenResponse);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("response");
        }
    }

    @PostMapping("/create-realm")
    public ResponseEntity<?> createRealm(@RequestParam(required = true) String realmName,
                                         @RequestHeader("Authorization") String token) {
        log.info("Create realm request received for realm: [{}]", realmName);
        try {
            keyCloakService.createRealm(token, realmName);
            log.info("Realm created successfully: [{}]", realmName);
            return ResponseEntity.status(HttpStatus.CREATED).build();
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("response");
        }
    }

    @PostMapping("/create-client")
    public ResponseEntity<?> createClient(@RequestParam(required = true) String realmName,
                                          @RequestHeader("Authorization") String token) {
        log.info("Create client request received for realm: [{}]", realmName);
        try {
            KCCreateClientResponse clientDetailsResponse = keyCloakService.createClient(token, realmName);
            log.info("Client created successfully for realm: [{}]", realmName);
            return ResponseEntity.status(HttpStatus.CREATED).body(clientDetailsResponse);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("response");
        }
    }

    @PostMapping("/create-roles")
    public ResponseEntity<?> createRoles(@RequestParam(required = true) String realmName,
                                         @RequestHeader("Authorization") String token,
                                         @RequestBody String[] roles) {
        log.info("Create roles request received for realm: [{}], roles: [{}]", realmName, Arrays.toString(roles));
        try {
            keyCloakService.createRoles(token, realmName,roles);
            log.info("Roles created successfully for realm: [{}]", realmName);
            return ResponseEntity.status(HttpStatus.CREATED).build();
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("response");
        }
    }

    @PostMapping("/create-group")
    public ResponseEntity<String> createGroup(@RequestParam(required = true) String groupName,
                                         @RequestHeader("Authorization") String token,
                                         @RequestParam(required = true) String realmName) {
        log.info("Create group request received for group: [{}], realm: [{}]", groupName, realmName);
        try {
            String groupId=keyCloakService.createGroup(token, groupName,realmName);
            log.info("Group created successfully: [{}] in realm: [{}]", groupId, realmName);
            return ResponseEntity.status(HttpStatus.CREATED).body(groupId);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("response");
        }
    }

    @PostMapping("/assign-group-roles")
    public ResponseEntity<String> assignGroupRoles(
            @RequestParam String groupId,
            @RequestParam String realmName,
            @RequestBody List<String> roles,
            @RequestHeader("Authorization") String token) {
        log.info("Assign group roles request received for group: [{}], realm: [{}], roles: [{}]", groupId, realmName, roles);
        try {
            keyCloakService.assignRolesToGroup(token, groupId, roles, realmName);
            log.info("Roles assigned successfully to group: [{}]", groupId);
            return ResponseEntity.status(HttpStatus.OK).body("Roles assigned successfully");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error assigning roles");
        }
    }

    @GetMapping("/get-all-realm-roles")
    public List<RealmRoleDetails> getAllRealmRoles(@RequestParam String realmName,
                                                   @RequestHeader("Authorization") String token) {
        log.info("Get all realm roles request received for realm: [{}]", realmName);
        List<RealmRoleDetails> roles = keyCloakService.getAllRealmRoles(token,realmName);
        log.info("Fetched [{}] roles for realm: [{}]", roles.size(), realmName);
        return roles;
    }

    @PostMapping("/onboard-first-user")
    public ResponseEntity<?> createFirstUser(
            @RequestHeader("Authorization") String token,
            @RequestBody KCFirstUserRequest userRequest) {
        log.info("Onboard first user request received for user: [{}], realm: [{}]", userRequest.getUserName(), userRequest.getRealmName());
        try {
            List<KCOnboardUserRequest.Credential> credential = List.of(KCOnboardUserRequest.Credential.builder()
                    .type("password")
                    .value(userRequest.getPassword())
                    .temporary(false)
                    .build());

            KCOnboardUserRequest kcOnboardUserRequest = KCOnboardUserRequest.builder()
                    .email(userRequest.getEmail())
                    .username(userRequest.getUserName())
                    .credentials(credential)
                    .enabled(true)
                    .build();

            String userId = keyCloakService.createUser(token, kcOnboardUserRequest, userRequest.getRealmName());
            Map<String, String> userResponse = new HashMap<>();
            userResponse.put("userId", userId);
            log.info("First user onboarded successfully: [{}] in realm: [{}]", userId, userRequest.getRealmName());
            return ResponseEntity.status(HttpStatus.CREATED).body(userResponse);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/grant-super-admin-access")
    public ResponseEntity<?> grantAdminAccess(@RequestHeader("Authorization") String token,
                                              @RequestParam(required = true) String realmName, @RequestParam(required = true) String userId,
                                              @RequestParam String groupId) {
        log.info("Grant super admin access request received for user: [{}], realm: [{}], group: [{}]", userId, realmName, groupId);
        try {
            keyCloakService.grantSuperAdminAccess(token, realmName, userId,groupId);
            log.info("Super admin access granted successfully to user: [{}]", userId);
            return ResponseEntity.status(HttpStatus.CREATED).build();
        } catch (Exception e) {
            e.printStackTrace();
           // HttpExceptionResponse response = httpExceptionResponseUtil.internalServerError(e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PostMapping("/validate-tenant")
    public ResponseEntity<?> validateTenant(@Valid @RequestBody KCValidateTenantRequest request) {

        log.info("Validate tenant request received for tenant: [{}]", request.getTenantName());

        KCAdminAccessTokenRequest keycloakTokenRequest = KCAdminAccessTokenRequest.builder()
                .clientId(Constants.CLIENT_ID_ADMIN_CLI)
                .username(Constants.CLIENT_ID_ADMIN_USERNAME)
                .password(Constants.CLIENT_ID_ADMIN_PASSWORD).build();

        String token = keyCloakService.getAdminAccessToken(keycloakTokenRequest);

        KCTenantInfoResponse response = keyCloakService.validateTenant("Bearer " + token, request.getTenantName());
        HttpDataResponse httpResponse = httpDataResponseUtil.resourceFetched(response);

        log.info("Tenant validated successfully: [{}]", request.getTenantName());
        return ResponseEntity.ok().body(httpResponse);

    }
    @PostMapping("/validate-authcode")
    public ResponseEntity<?> validateAuthCodeAndSetTokenAsCookies(
            @Valid @RequestBody KCRealmAccessTokenRequest request) {

        log.info("Auth code validation started: {}", "inside /validate-authcode epts");
        KCRealmAccessTokenResponse kcRealmAccessTokenResponse = keyCloakService.validateAuthCode(request);
        log.info("Successfully completed the request, response sent");
        return ResponseEntity.status(HttpStatus.CREATED).body(kcRealmAccessTokenResponse);
    }



    @PostMapping("/onboard-kc-user")
    public ResponseEntity<?> createUser(
            @RequestHeader("Authorization") String token,
            @RequestBody KCFirstUserRequest userRequest) {
        log.info("Onboard user request received for user: [{}], realm: [{}]", userRequest.getUserName(), userRequest.getRealmName());
        try {
            List<KCOnboardUserRequest.Credential> credential = List.of(KCOnboardUserRequest.Credential.builder()
                    .type("password")
                    .value(userRequest.getPassword())
                    .temporary(userRequest.isTemporaryPassword())
                    .build());

            KCOnboardUserRequest kcOnboardUserRequest = KCOnboardUserRequest.builder()
                    .email(userRequest.getEmail())
                    .username(userRequest.getUserName())
                    .credentials(credential)
                    .enabled(true)
                    .build();

            String userId = keyCloakService.createUser(token, kcOnboardUserRequest, userRequest.getRealmName());
            Map<String, String> userResponse = new HashMap<>();
            userResponse.put("userId", userId);
            log.info("User onboarded successfully: [{}] in realm: [{}]", userId, userRequest.getRealmName());
            return ResponseEntity.status(HttpStatus.CREATED).body(userResponse);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @DeleteMapping("/remove-group-access")
    public ResponseEntity<?> removeGroupAccess(@RequestHeader("Authorization") String token,
                                              @RequestParam(required = true) String realmName,
                                               @RequestParam(required = true) String userId,
                                              @RequestParam String groupId) {
        log.info("Remove group access request received for user: [{}], realm: [{}], group: [{}]", userId, realmName, groupId);
        try {
            keyCloakService.removeGroupAccess(token, realmName, userId,groupId);
            log.info("Group access removed successfully for user: [{}]", userId);
            return ResponseEntity.status(HttpStatus.OK).build();
        } catch (Exception e) {
            e.printStackTrace();
           // HttpExceptionResponse response = httpExceptionResponseUtil.internalServerError(e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @DeleteMapping("/remove-group-roles")
    public ResponseEntity<?> removeGroupRoles(@RequestHeader("Authorization") String token,
                                              @RequestParam(required = true) String realmName,
                                              @RequestParam(required = true) String groupId,
                                              @RequestBody List<String> roles) {
        log.info("Remove group roles request received for group: [{}], realm: [{}], roles: [{}]", groupId, realmName, roles);
        try {
            keyCloakService.removeRolesFromGroup(token, groupId, roles, realmName);
            log.info("Roles removed successfully from group: [{}]", groupId);
            return ResponseEntity.status(HttpStatus.OK).build();
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PutMapping("/update-group-name")
    public ResponseEntity<String> updateGroupName(@RequestParam String groupId,
                                                  @RequestParam String newGroupName,
                                                  @RequestParam String realmName,
                                                  @RequestHeader("Authorization") String token) {
        log.info("Update group name request received for group: [{}], newName: [{}], realm: [{}]", groupId, newGroupName, realmName);
        try {
            keyCloakService.updateGroupName(token, groupId, newGroupName, realmName);
            log.info("Group name updated successfully for group: [{}]", groupId);
            return ResponseEntity.status(HttpStatus.OK).body("Group name updated successfully");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error updating group name");
        }
    }
    

}

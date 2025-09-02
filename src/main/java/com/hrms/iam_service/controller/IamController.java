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


import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

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
        try {
            String token = keyCloakService.getAdminAccessToken(request);
            Map<String, String> tokenResponse = new HashMap<>();
            tokenResponse.put("token", token);
            return ResponseEntity.status(HttpStatus.CREATED).body(tokenResponse);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("response");
        }
    }

    @PostMapping("/create-realm")
    public ResponseEntity<?> createRealm(@RequestParam(required = true) String realmName,
                                         @RequestHeader("Authorization") String token) {
        try {
            keyCloakService.createRealm(token, realmName);
            return ResponseEntity.status(HttpStatus.CREATED).build();
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("response");
        }
    }

    @PostMapping("/create-client")
    public ResponseEntity<?> createClient(@RequestParam(required = true) String realmName,
                                          @RequestHeader("Authorization") String token) {
        try {
            KCCreateClientResponse clientDetailsResponse = keyCloakService.createClient(token, realmName);
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
        try {
            keyCloakService.createRoles(token, realmName,roles);
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
        try {
            String groupId=keyCloakService.createGroup(token, groupName,realmName);
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
        try {
            keyCloakService.assignRolesToGroup(token, groupId, roles, realmName);
            return ResponseEntity.status(HttpStatus.OK).body("Roles assigned successfully");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error assigning roles");
        }
    }

    @GetMapping("/get-all-realm-roles")
    public List<RealmRoleDetails> getAllRealmRoles(@RequestParam String realmName,
                                                   @RequestHeader("Authorization") String token) {
        return keyCloakService.getAllRealmRoles(token,realmName);
    }

    @PostMapping("/onboard-first-user")
    public ResponseEntity<?> createFirstUser(
            @RequestHeader("Authorization") String token,
            @RequestBody KCFirstUserRequest userRequest) {
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
        try {
            keyCloakService.grantSuperAdminAccess(token, realmName, userId,groupId);
            return ResponseEntity.status(HttpStatus.CREATED).build();
        } catch (Exception e) {
            e.printStackTrace();
           // HttpExceptionResponse response = httpExceptionResponseUtil.internalServerError(e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PostMapping("/validate-tenant")
    public ResponseEntity<?> validateTenant(@Valid @RequestBody KCValidateTenantRequest request) {

        KCAdminAccessTokenRequest keycloakTokenRequest = KCAdminAccessTokenRequest.builder()
                .clientId(Constants.CLIENT_ID_ADMIN_CLI)
                .username(Constants.CLIENT_ID_ADMIN_USERNAME)
                .password(Constants.CLIENT_ID_ADMIN_PASSWORD).build();

        String token = keyCloakService.getAdminAccessToken(keycloakTokenRequest);

        KCTenantInfoResponse response = keyCloakService.validateTenant("Bearer " + token, request.getTenantName());
        HttpDataResponse httpResponse = httpDataResponseUtil.resourceFetched(response);

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
            return ResponseEntity.status(HttpStatus.CREATED).body(userResponse);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
     
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request,
                                       HttpServletResponse response) {
        String realm =request.getHeader("X-Tenant-Id");
        String redirectUri = "https://demo.pp.hrms.work/tenant-login";
                
        String idToken = request.getHeader("Authorization").replace("Bearer ", ""); // or however you stored it

        String logoutUrl = keycloakBaseUrl + "realms/" + realm +
            "/protocol/openid-connect/logout?id_token_hint=" + idToken +
            "&post_logout_redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);
            
        log.info("Redirecting to Keycloak logout URL: {}", logoutUrl);

        // return 302 to UI → browser follows to Keycloak
        response.setHeader("Location", logoutUrl);
        response.setStatus(HttpServletResponse.SC_FOUND);
        return ResponseEntity.status(HttpStatus.FOUND).build();
    }



}

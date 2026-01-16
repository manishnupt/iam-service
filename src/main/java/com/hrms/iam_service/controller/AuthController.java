package com.hrms.iam_service.controller;

import com.hrms.iam_service.dto.KCAdminAccessTokenRequest;
import com.hrms.iam_service.dto.TokenRequest;
import com.hrms.iam_service.dto.TokenResponse;
import com.hrms.iam_service.service.KeycloakService;
import jakarta.validation.Valid;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins="*")
@Log4j2
public class AuthController {

    @Autowired
    private KeycloakService keycloakService;


    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refreshToken(
            @Valid @RequestBody TokenRequest request
                    ,@RequestHeader("X-Tenant-Id") String tenantId) {
        try {
            TokenResponse response = keycloakService.refreshToken(
                    request.getRefreshToken(),tenantId
            );

            log.info("Token refreshed successfully for tenant: [{}]", tenantId);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Token refresh failed for tenant: [{}] - {}", tenantId, e.getMessage());
            throw e;
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @RequestHeader("X-Tenant-Id") String tenantId,
            @Valid @RequestBody TokenRequest request) {

        log.info("Logout request for tenant: [{}]", tenantId);

        try {
           // tokenRefreshService.logout(request.getRefreshToken(), tenantId);
            log.info("Logout successful for tenant: [{}]", tenantId);
            return ResponseEntity.noContent().build();

        } catch (Exception e) {
            log.error("Logout failed for tenant: [{}] - {}", tenantId, e.getMessage());
            throw e;
        }
    }

}



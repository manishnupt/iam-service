package com.hrms.iam_service.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class KCAdminAccessTokenRequest {
    private String tenantName;
    private String clientId;
    private String clientSecret;
    private String username;
    private String password;
}

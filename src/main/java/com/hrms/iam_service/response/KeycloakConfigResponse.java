package com.hrms.iam_service.response;

import lombok.Data;

@Data
public class KeycloakConfigResponse {
    private String code;
    private String message;
    private ConfigData data;

    @Data
    public static class ConfigData {
        private String clientId;
        private String clientSecret;
        private String realm;
        private String username;
        private String password;
    }

}

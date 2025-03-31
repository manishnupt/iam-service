package com.hrms.iam_service.response;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@NoArgsConstructor
@AllArgsConstructor
public class KCRealmAccessTokenResponse {

    private String access_token;
    private int expires_in;
    private String refresh_token;
    private int refresh_expires_in;
    private String token_type;
    private String session_state;
    private String scope;

}

package com.hrms.iam_service.utility;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hrms.iam_service.response.HttpDataResponse;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class HttpDataResponseUtil {

    public HttpDataResponse responseBuilder(int code, String message, Object data) {
        return HttpDataResponse.builder()
                .code(code)
                .message(message)
                .data(data)
                .build();
    }

    public <T> HttpDataResponse resourceFetched(T resource) {
        Object serializedResource = serializeToJson(resource);

        return HttpDataResponse.builder()
                .code(Constants.RESOURCE_OK_CODE)
                .message("Resources fetched successfully.")
                .data(serializedResource)
                .build();
    }

    public <T> HttpDataResponse resourceCreated(T resource) {
        Object serializedResource = serializeToJson(resource);

        return HttpDataResponse.builder()
                .code(Constants.RESOURCE_CREATED_CODE)
                .message("Resources created successfully.")
                .data(serializedResource)
                .build();
    }

    public <T> HttpDataResponse resourceUpdated(T resource) {
        Object serializedResource = serializeToJson(resource);

        return HttpDataResponse.builder()
                .code(Constants.RESOURCE_OK_CODE)
                .message("Resource updated successfully.")
                .data(serializedResource)
                .build();
    }

    public <T> HttpDataResponse resourceDeleted(T resource) {
        Object serializedResource = serializeToJson(resource);

        return HttpDataResponse.builder()
                .code(Constants.RESOURCE_OK_CODE)
                .message("Resource deleted successfully.")
                .data(serializedResource)
                .build();
    }

    private <T> Object serializeToJson(T resource) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            return objectMapper.convertValue(resource, Object.class);
        } catch (Exception e) {
            return Map.of("error", "Error serializing resource: " + e.getMessage());
        }
    }

}

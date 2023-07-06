package com.promise.controller;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.HashMap;
import java.util.Map;

@Data
@AllArgsConstructor
public class Result {
    private Integer code;
    private String message;
    private Map<String, Object> data = new HashMap<>();

    public Result(Integer code, String message) {
        this.code = code;
        this.message = message;
    }
}

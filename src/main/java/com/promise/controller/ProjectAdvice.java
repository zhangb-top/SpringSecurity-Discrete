package com.promise.controller;

import com.promise.exception.TokenException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ProjectAdvice {
    @ExceptionHandler(TokenException.class)
    public Result doTokenException(TokenException e) {
        return new Result(Code.CODE_FAIL, e.getMessage());
    }
}

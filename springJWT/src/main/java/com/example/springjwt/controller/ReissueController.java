package com.example.springjwt.controller;

import static com.example.springjwt.enums.ReissueMessage.REFRESH_EXPIRED;
import static com.example.springjwt.enums.ReissueMessage.REFRESH_INVALID;
import static com.example.springjwt.enums.ReissueMessage.REFRESH_NULL;

import com.example.springjwt.service.ReissueService;
import com.example.springjwt.util.CookieMethods;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
@RequiredArgsConstructor
public class ReissueController {

    private final ReissueService reissueService;
    private final CookieMethods cookieMethods;

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {

        String refresh = reissueService.reissueToken(request);

        if (refresh.equals(REFRESH_NULL.getMessage())) {
            return new ResponseEntity<>(REFRESH_NULL.getMessage(), HttpStatus.BAD_REQUEST);
        }
        if (refresh.equals(REFRESH_EXPIRED.getMessage())) {
            return new ResponseEntity<>(REFRESH_EXPIRED.getMessage(), HttpStatus.BAD_REQUEST);
        }
        if (refresh.equals(REFRESH_INVALID.getMessage())) {
            return new ResponseEntity<>(REFRESH_INVALID.getMessage(), HttpStatus.BAD_REQUEST);
        }

        String newAccess = reissueService.getNewAccess(refresh);
        response.setHeader("access", newAccess);

        // 새로운 RefreshToken 발급
        String newRefresh = reissueService.getNewRefresh(refresh);
        response.addCookie(cookieMethods.createCookie("refresh", newRefresh));

        return new ResponseEntity<>(HttpStatus.OK);
    }


}
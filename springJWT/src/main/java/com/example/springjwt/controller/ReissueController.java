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

        // DB에 RefreshToken이 존재하는지 확인 -> LoginFilter에서 이미 저장을 했을 것이기 때문이다.
        Boolean isExist = reissueService.checkRefresh(refresh);
        if (!isExist) {
            return new ResponseEntity<>(REFRESH_INVALID, HttpStatus.BAD_REQUEST);
        }

        String newAccess = reissueService.getNewAccess(refresh);
        // 새로운 RefreshToken 발급
        String newRefresh = reissueService.getNewRefresh(refresh);

        // DB에 저장되어있던 RefreshToken을 삭제하고 새로운 RefreshToken을 추가한다.
        reissueService.rotateRefresh(newRefresh, refresh);

        response.setHeader("access", newAccess);
        response.addCookie(cookieMethods.createCookie("refresh", newRefresh));

        return new ResponseEntity<>(HttpStatus.OK);
    }


}
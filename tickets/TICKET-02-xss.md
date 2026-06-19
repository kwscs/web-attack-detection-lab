# TICKET-02 Reflected XSS

## 탐지 개요

- 발생 날짜 : 2026-06-08 08:45~08:56, 2026-06-05 13:07~13:12
- 출발지 IP : 192.168.122.96
- 대상 : 192.168.122.20
- 심각도 : High
- 탐지 룰 : docs/02_xss.md
- 분류 : OWASP XSS / CWE-79

## 분석

접근 로그에서 `/vulnerabilities/xss_r/` 경로로 `<script>`, `%3Cscript`, `onerror`, `onload`, `javascript:`, `document.cookie` 시그니처가 포함된 요청 8건이 탐지되었다. 모두 192.168.122.96에서 발생했고 응답코드는 200이므로 요청이 차단되지 않고 애플리케이션에서 처리된 것으로 확인된다.
디코딩된 페이로드에서는 `<script>alert(1)</script>`, `<script>alert(document.cookie)</script>`, `<img src=a onerror=alert(1)>`, `<svg onload=alert(1)>`, `javascript:alert(1)` 등 Reflected XSS 공격에 사용되는 패턴이 확인되었다.

## 판단

정탐으로 판단했다.
Apache 접근 로그에서 `<script>`, `onerror`, `onload`, `javascript:`, `document.cookie` 등 XSS 공격에 사용되는 문자열이 확인되었고 동일한 출발지 IP에서 `/vulnerabilities/xss_r/` 경로로 반복 요청이 발생했다.

## 조치

- 출력 시 입력값 HTML 인코딩 처리
- 세션 쿠키에 HttpOnly, Secure 속성 적용 (현재 미적용 상태)

## 근거 화면

### XSS 탐지 결과

![XSS 탐지 결과](../screenshots/02_xss_payloads.png)

### 공격자 IP 기준 집계

![공격자 IP 기준 집계](../screenshots/02_xss_attacker_ip.png)
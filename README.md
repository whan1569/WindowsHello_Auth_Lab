# WindowsHello_Auth_Lab

GMT Hub 관리자 PC 1대 제한에 적용하기 전 Windows Hello/WebAuthn을 검증하는 최소 테스트베드입니다.

## 실행

```powershell
pip install -r requirements.txt
uvicorn app:app --reload
```

브라우저에서 `http://localhost:8000` 접속 후:

1. **관리자 PC 등록** — 최초 1회 Windows Hello 인증 후 공개키 저장
2. **Windows Hello 인증** — 서버 challenge에 대해 Windows Hello 인증
3. 성공 시 `ADMIN DEVICE VERIFIED`

등록 정보는 로컬 `credential.json`에 저장됩니다. 개인키/Windows Hello 생체정보는 서버에 저장하지 않습니다.

> 이 저장소는 기술 검증용입니다. GMT Hub 통합 전 challenge 저장 방식, 세션 바인딩, HTTPS/RP ID, credential 관리 정책을 별도로 적용해야 합니다.

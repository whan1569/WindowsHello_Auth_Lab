import json
import secrets
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

app = FastAPI(title="Windows Hello Auth Lab")
STORE = Path(__file__).with_name("credential.json")
RP_ID = "localhost"
ORIGIN = "http://localhost:8000"
USER_ID = b"gmt-admin"
register_challenge: bytes | None = None
auth_challenge: bytes | None = None


class CredentialResponse(BaseModel):
    response: dict


def load_credential():
    if not STORE.exists():
        return None
    return json.loads(STORE.read_text(encoding="utf-8"))


@app.get("/", response_class=HTMLResponse)
def index():
    return Path(__file__).with_name("index.html").read_text(encoding="utf-8")


@app.post("/register/begin")
def register_begin():
    global register_challenge
    if load_credential():
        raise HTTPException(409, "An admin credential is already registered")
    register_challenge = secrets.token_bytes(32)
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name="GMT Windows Hello Lab",
        user_id=USER_ID,
        user_name="GMT Administrator",
        user_display_name="GMT Administrator",
        challenge=register_challenge,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    return json.loads(options_to_json(options))


@app.post("/register/finish")
def register_finish(body: CredentialResponse):
    global register_challenge
    if register_challenge is None:
        raise HTTPException(400, "Registration challenge missing")
    try:
        verified = verify_registration_response(
            credential=body.response,
            expected_challenge=register_challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            require_user_verification=True,
        )
    except Exception as exc:
        raise HTTPException(400, f"Registration failed: {exc}") from exc
    data = {
        "credential_id": verified.credential_id.hex(),
        "public_key": verified.credential_public_key.hex(),
        "sign_count": verified.sign_count,
    }
    STORE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    register_challenge = None
    return {"status": "REGISTERED"}


@app.post("/verify/begin")
def verify_begin():
    global auth_challenge
    saved = load_credential()
    if not saved:
        raise HTTPException(404, "No admin credential registered")
    auth_challenge = secrets.token_bytes(32)
    options = generate_authentication_options(
        rp_id=RP_ID,
        challenge=auth_challenge,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return json.loads(options_to_json(options))


@app.post("/verify/finish")
def verify_finish(body: CredentialResponse):
    global auth_challenge
    saved = load_credential()
    if not saved or auth_challenge is None:
        raise HTTPException(400, "Authentication challenge missing")
    try:
        verified = verify_authentication_response(
            credential=body.response,
            expected_challenge=auth_challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=bytes.fromhex(saved["public_key"]),
            credential_current_sign_count=int(saved.get("sign_count", 0)),
            require_user_verification=True,
        )
    except Exception as exc:
        raise HTTPException(401, f"Authentication failed: {exc}") from exc
    saved["sign_count"] = verified.new_sign_count
    STORE.write_text(json.dumps(saved, indent=2), encoding="utf-8")
    auth_challenge = None
    return {"status": "ADMIN DEVICE VERIFIED"}

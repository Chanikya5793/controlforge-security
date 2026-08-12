"""Maintained py_webauthn adapter behind a small testable service contract."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Protocol, cast

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)


def credential_id_text(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class RegistrationVerification:
    credential_id: str
    public_key: bytes
    sign_count: int


@dataclass(frozen=True)
class AuthenticationVerification:
    credential_id: str
    new_sign_count: int


class PasskeyAdapter(Protocol):
    def registration_options(
        self,
        user_id: str,
        user_name: str,
        display_name: str,
        challenge: bytes,
        exclude_credential_ids: list[str],
    ) -> dict[str, object]:
        """Create browser registration options for a known challenge."""

    def verify_registration(
        self,
        response: dict[str, object],
        challenge: bytes,
    ) -> RegistrationVerification:
        """Verify a browser registration result."""

    def authentication_options(
        self,
        challenge: bytes,
        credential_ids: list[str],
    ) -> dict[str, object]:
        """Create browser authentication options for known credentials."""

    def response_credential_id(self, response: dict[str, object]) -> str:
        """Extract the encoded credential identity before assertion verification."""

    def verify_authentication(
        self,
        response: dict[str, object],
        challenge: bytes,
        public_key: bytes,
        current_sign_count: int,
    ) -> AuthenticationVerification:
        """Verify a browser assertion against stored public credential material."""


class WebAuthnPasskeyAdapter:
    """Production adapter using the maintained `webauthn` package."""

    def __init__(self, rp_id: str, rp_name: str, expected_origin: str) -> None:
        if not rp_id or not rp_name or not expected_origin.startswith("https://"):
            raise ValueError("passkey relying-party configuration is invalid")
        self._rp_id = rp_id
        self._rp_name = rp_name
        self._expected_origin = expected_origin.rstrip("/")

    @staticmethod
    def _credential_bytes(value: str) -> bytes:
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(f"{value}{padding}")

    def registration_options(
        self,
        user_id: str,
        user_name: str,
        display_name: str,
        challenge: bytes,
        exclude_credential_ids: list[str],
    ) -> dict[str, object]:
        options = generate_registration_options(
            rp_id=self._rp_id,
            rp_name=self._rp_name,
            user_id=user_id.encode("utf-8"),
            user_name=user_name,
            user_display_name=display_name,
            challenge=challenge,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=self._credential_bytes(credential_id))
                for credential_id in exclude_credential_ids
            ],
        )
        return cast(dict[str, object], json.loads(options_to_json(options)))

    def verify_registration(
        self,
        response: dict[str, object],
        challenge: bytes,
    ) -> RegistrationVerification:
        verified = verify_registration_response(
            credential=response,
            expected_challenge=challenge,
            expected_rp_id=self._rp_id,
            expected_origin=self._expected_origin,
            require_user_verification=True,
        )
        return RegistrationVerification(
            credential_id=credential_id_text(verified.credential_id),
            public_key=verified.credential_public_key,
            sign_count=verified.sign_count,
        )

    def authentication_options(
        self,
        challenge: bytes,
        credential_ids: list[str],
    ) -> dict[str, object]:
        options = generate_authentication_options(
            rp_id=self._rp_id,
            challenge=challenge,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=self._credential_bytes(credential_id))
                for credential_id in credential_ids
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return cast(dict[str, object], json.loads(options_to_json(options)))

    def response_credential_id(self, response: dict[str, object]) -> str:
        credential_id = response.get("id")
        if not isinstance(credential_id, str) or not credential_id:
            raise ValueError("passkey response has no credential identity")
        return credential_id.rstrip("=")

    def verify_authentication(
        self,
        response: dict[str, object],
        challenge: bytes,
        public_key: bytes,
        current_sign_count: int,
    ) -> AuthenticationVerification:
        verified = verify_authentication_response(
            credential=response,
            expected_challenge=challenge,
            expected_rp_id=self._rp_id,
            expected_origin=self._expected_origin,
            credential_public_key=public_key,
            credential_current_sign_count=current_sign_count,
            require_user_verification=True,
        )
        return AuthenticationVerification(
            credential_id=credential_id_text(verified.credential_id),
            new_sign_count=verified.new_sign_count,
        )

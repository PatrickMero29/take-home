"""PyOTP adapter; a match is an input to authentication policy, not an assurance grant."""

from datetime import UTC, datetime

import pyotp
from pydantic import SecretStr


class TotpEngine:
    def __init__(self, *, interval: int = 30, window: int = 1) -> None:
        if interval <= 0 or not 0 <= window <= 1:
            raise ValueError("TOTP requires a positive interval and a bounded drift window")
        self.interval = interval
        self.window = window

    def matched_counter(self, secret: SecretStr, code: SecretStr, *, now: int) -> int | None:
        value = code.get_secret_value()
        if len(value) != 6 or not value.isascii() or not value.isdecimal():
            return None
        otp = pyotp.TOTP(secret.get_secret_value(), interval=self.interval)
        counter = now // self.interval
        for candidate in range(max(0, counter - self.window), counter + self.window + 1):
            instant = datetime.fromtimestamp(candidate * self.interval, UTC)
            if otp.verify(value, for_time=instant, valid_window=0):
                return candidate
        return None

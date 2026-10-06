import re

import pandas as pd


# ============================================================
# CYBERGUARD
# DIGITAL IMPERSONATION DETECTION ENGINE
#
# Six detectors run over reported impersonation messages
# (SMS, email, chat, social comment, QR, caller notes).
#
# The module never requires an "is_impersonation" label:
# it derives every verdict from the message content, the
# claimed identity, the channel and the reporting context.
# ============================================================


# ============================================================
# INPUT SAFETY HELPERS
# ============================================================

def _prepare_messages(
    messages,
    required_columns=None,
    optional_columns=None
):

    if messages is None or not isinstance(
        messages,
        pd.DataFrame
    ):
        return None, list(required_columns or [])

    messages = messages.copy()

    required_columns = list(required_columns or [])
    optional_columns = list(optional_columns or [])

    missing_required = [
        column
        for column in required_columns
        if column not in messages.columns
    ]

    if missing_required:
        return None, missing_required

    for column in optional_columns:
        if column not in messages.columns:
            messages[column] = ""

    return messages, []


def _empty_result(columns):
    return pd.DataFrame(columns=columns)


def ensure_message_id(messages):
    """
    Guarantee a message_id column.

    message_id is the grouping key for the risk engine, so a
    CSV that omits the column entirely must still be analysed
    rather than silently returning zero detections. Identifiers
    are synthesised from the row position.
    """

    if (
        "message_id" in messages.columns
        and messages["message_id"].notna().any()
    ):
        # Fill only the gaps so a partially populated column
        # does not produce colliding identifiers.
        messages["message_id"] = messages[
            "message_id"
        ].fillna("")

        missing = (
            messages["message_id"]
            .astype(str)
            .str.strip() == ""
        )

        if missing.any():
            messages.loc[missing, "message_id"] = [
                f"message_{index}"
                for index in messages.index[missing]
            ]

        return messages

    messages["message_id"] = [
        f"message_{index}"
        for index in range(len(messages))

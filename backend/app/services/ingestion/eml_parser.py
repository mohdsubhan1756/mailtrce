
from email import policy
from email.parser import BytesParser
from email.message import Message


def parse_eml(
    raw_email: bytes
) -> Message:
    """
    Parse raw EML bytes using the standard
    Python email parser.
    """

    parser = BytesParser(
        policy=policy.default
    )

    message = parser.parsebytes(
        raw_email
    )

    return message
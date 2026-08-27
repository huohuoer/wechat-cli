"""不可信微信 XML 的有界解析。"""

import re
import xml.etree.ElementTree as ET


XML_PARSE_MAX_LEN = 20_000
_UNSAFE_DECLARATION = re.compile(r"<!DOCTYPE|<!ENTITY", re.IGNORECASE)


def parse_untrusted_xml(content, *, max_length=XML_PARSE_MAX_LEN):
    if not isinstance(content, str) or not content or len(content) > max_length:
        return None
    if _UNSAFE_DECLARATION.search(content):
        return None
    try:
        return ET.fromstring(content)
    except (ET.ParseError, RecursionError):
        return None

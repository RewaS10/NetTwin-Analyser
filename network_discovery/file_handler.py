from __future__ import annotations

from typing import Iterable

from network_discovery.parsers.cisco_parser import parse_cisco_config
from network_discovery.models import NetworkDevice


SUPPORTED_EXTENSIONS = {
    ".txt",
    ".cfg",
    ".conf",
    ".config",
}


def is_supported_file(filename: str) -> bool:
    """Check whether the uploaded file has a supported extension."""

    filename = filename.lower()

    return any(
        filename.endswith(extension)
        for extension in SUPPORTED_EXTENSIONS
    )


def read_uploaded_file(uploaded_file) -> str:
    """
    Read a Streamlit uploaded file and return its text content.
    """

    content = uploaded_file.getvalue()

    return content.decode(
        "utf-8",
        errors="ignore",
    )


def parse_uploaded_files(
    uploaded_files: Iterable,
) -> tuple[list[NetworkDevice], list[str]]:
    """
    Parse multiple uploaded network configuration files.

    Returns:
        devices: Successfully parsed network devices.
        errors: Files that could not be processed.
    """

    devices: list[NetworkDevice] = []
    errors: list[str] = []

    for uploaded_file in uploaded_files:

        filename = uploaded_file.name

        if not is_supported_file(filename):
            errors.append(
                f"{filename}: Unsupported file type"
            )
            continue

        try:

            config_text = read_uploaded_file(
                uploaded_file
            )

            if not config_text.strip():
                errors.append(
                    f"{filename}: File is empty"
                )
                continue

            device = parse_cisco_config(
                config_text,
                source_file=filename,
            )

            devices.append(device)

        except Exception as error:

            errors.append(
                f"{filename}: {error}"
            )

    return devices, errors
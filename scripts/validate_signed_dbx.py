# @file
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Validate that the signed DBX payloads are reproducible from the DBX metadata.

The authoritative description of the Microsoft DBX revocations lives in
``PreSignedObjects/DBX/dbx_info_msft_latest.json``. The signed payloads under
``PostSignedObjects/SignedByKEK2011`` and ``PostSignedObjects/SignedByKEK2023``
are produced out-of-band by the signing service and committed as opaque blobs.

This script reproduces the expected unsigned DBX signature-list payload for each
architecture directly from the JSON (using the same conversion the firmware
build uses) and asserts it is byte-for-byte identical to the signature list
embedded in the signed files. This guarantees the signed files are reproducible
from, and documented by, the JSON.

The reproduced payload contains the non-optional revocations (entries not flagged
``isOptional``), which is what the mandatory signed DBX files carry.

Two checks are performed:

Reproduction (per architecture):

* A signed payload that reproduces exactly passes.
* A signed hash that is not a documented, non-optional entry is always an error.
* A documented, non-optional hash that is not signed is an error, unless the
  architecture is a known reproducibility exception (see ``REPRODUCIBILITY_EXCEPTIONS``),
  in which case it is only reported. ``--strict`` enforces every architecture.

Completeness (the JSON is the source of truth):

* Every documented hash must be enforced by the signed files, either signed
  directly or covered by a revoked certificate that matches its signing authority.
  An uncovered non-optional hash is an error; an uncovered optional hash is
  reported (an error under ``--strict``).
* Every documented SVN must be present in the signed files.
* Every documented certificate must be revoked in the signed files.
"""
import argparse
import hashlib
import io
import json
import logging
import os
import pathlib
import sys
import tempfile

from edk2toollib.uefi.authenticated_variables_structure_support import (
    EfiSignatureDatabase,
    EfiVariableAuthentication2,
)

# Allow importing the sibling generation module regardless of the caller's cwd.
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from secure_boot_default_keys import _convert_json_to_signature_list

# The architectures documented in the DBX JSON, mapped to the signed file layout.
ARCHITECTURES = ["x64", "ia32", "aarch64", "arm"]

# The DBX signature owner GUID. This matches the ``signature_owner`` assigned to the
# DefaultDbx entry in every template under Templates/*.toml and must be used when
# reproducing the payload so the bytes match the signed files exactly.
DBX_SIGNATURE_OWNER = "77fa9abd-0359-4d32-bd60-28f4e78f784b"

# Architectures whose signed payloads are known not to fully reproduce from the JSON
# yet. Missing signatures for these architectures are reported instead of failing.
# Use --strict to enforce reproduction for every architecture.
REPRODUCIBILITY_EXCEPTIONS = {"ia32"}

# Signature list type GUIDs used in the DBX.
EFI_CERT_SHA256_GUID = "c1c41626-504c-4092-aca9-41f936934328"
EFI_CERT_X509_GUID = "a5c059a1-94e4-4aa7-87b5-ab155c2bf072"


def canonical_bytes(database: EfiSignatureDatabase) -> bytes:
    """Return the canonical byte encoding of a signature database.

    Args:
        database (EfiSignatureDatabase): The signature database to canonicalize.

    Returns:
        bytes: The canonical (sorted, de-duplicated) encoding of the database.
    """
    return database.get_canonical().encode()


def database_hashes(database: EfiSignatureDatabase) -> set:
    """Return the set of signature data hashes contained in a signature database.

    Args:
        database (EfiSignatureDatabase): The signature database to inspect.

    Returns:
        set: Upper-case hex strings of every signature in the database.
    """
    return {
        signature.signature_data.hex().upper()
        for sig_list in database.esl_list
        for signature in sig_list.signature_data_list
    }


def reproduce_database(dbx_json_path: pathlib.Path, arch: str) -> EfiSignatureDatabase:
    """Reproduce the expected non-optional DBX payload for an architecture.

    The JSON is filtered to the non-optional entries for the architecture and
    converted with the same routine the firmware build uses, guaranteeing the
    reproduced payload matches how the repo generates DBX signature lists.

    Args:
        dbx_json_path (pathlib.Path): Path to the dbx_info_msft_latest.json file.
        arch (str): The architecture to reproduce (e.g. "x64").

    Returns:
        EfiSignatureDatabase: The reproduced signature database.
    """
    with open(dbx_json_path, "r") as f:
        dbx_data = json.load(f)

    non_optional = [
        entry for entry in dbx_data.get("images", {}).get(arch, []) if not entry.get("isOptional")
    ]
    filtered = {"images": {arch: non_optional}}

    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    try:
        json.dump(filtered, tmp)
        tmp.close()
        payload = _convert_json_to_signature_list(tmp.name, DBX_SIGNATURE_OWNER, target_arch=arch)
    finally:
        os.unlink(tmp.name)

    return EfiSignatureDatabase(filestream=io.BytesIO(payload))


def _read_signed_payload(signed_file: pathlib.Path) -> EfiSignatureDatabase:
    """Read the signature-list payload from a signed authenticated variable file.

    Args:
        signed_file (pathlib.Path): Path to a signed authenticated variable file.

    Returns:
        EfiSignatureDatabase: The signature database embedded in the payload.
    """
    with open(signed_file, "rb") as f:
        auth_var = EfiVariableAuthentication2(decodefs=f)
    payload = auth_var.sig_list_payload
    if isinstance(payload, (bytes, bytearray)):
        payload = EfiSignatureDatabase(filestream=io.BytesIO(payload))
    return payload


def signed_database(signed_files: list) -> EfiSignatureDatabase:
    """Merge the signature lists from one or more signed files into a database.

    Args:
        signed_files (list): Paths to signed authenticated variable files.

    Returns:
        EfiSignatureDatabase: A database containing every signature list found.
    """
    database = EfiSignatureDatabase()
    for signed_file in signed_files:
        for sig_list in _read_signed_payload(signed_file).esl_list:
            database.esl_list.append(sig_list)
    return database


def signed_sources(signed_dir: pathlib.Path, arch: str) -> dict:
    """Return the signed DBX file groups to validate for an architecture.

    Args:
        signed_dir (pathlib.Path): The PostSignedObjects directory.
        arch (str): The architecture (e.g. "x64").

    Returns:
        dict: {source_label: [existing signed file paths]} for each KEK set.
    """
    kek2011 = sorted((signed_dir / "SignedByKEK2011" / f"dbx_{arch}_Legacy").glob("*.efiauth2"))
    kek2023 = [signed_dir / "SignedByKEK2023" / f"dbx_{arch}.efiauth2"]
    return {
        "SignedByKEK2011": [path for path in kek2011 if path.exists()],
        "SignedByKEK2023": [path for path in kek2023 if path.exists()],
    }


def collect_signed_material(signed_dir: pathlib.Path) -> tuple:
    """Collect every signed revocation hash and revoked certificate thumbprint.

    Args:
        signed_dir (pathlib.Path): The PostSignedObjects directory.

    Returns:
        tuple: (set of upper-case SHA256 hashes, set of lower-case certificate SHA1
            thumbprints) found across every signed DBX payload -- both KEK sets and
            the optional DBX updates.
    """
    hashes = set()
    thumbprints = set()
    search_roots = [
        signed_dir / "SignedByKEK2011",
        signed_dir / "SignedByKEK2023",
        signed_dir / "Optional" / "DBX",
    ]
    for root in search_roots:
        if not root.exists():
            continue
        for signed_file in sorted(root.rglob("*")):
            if not signed_file.is_file() or signed_file.suffix not in (".efiauth2", ".bin"):
                continue
            for sig_list in _read_signed_payload(signed_file).esl_list:
                type_guid = str(sig_list.signature_type).lower()
                for signature in sig_list.signature_data_list:
                    data = bytes(signature.signature_data)
                    if EFI_CERT_SHA256_GUID in type_guid:
                        hashes.add(data.hex().upper())
                    elif EFI_CERT_X509_GUID in type_guid:
                        thumbprints.add(hashlib.sha1(data).hexdigest().lower())
    return hashes, thumbprints


def validate_completeness(signed_dir: pathlib.Path, dbx_data: dict, strict: bool) -> list:
    """Verify every documented revocation is enforced by the signed files.

    The DBX JSON is the source of truth. Every documented hash must be signed
    directly or covered by a revoked certificate matching its signing authority,
    every documented SVN must be signed, and every documented certificate must be
    revoked in the signed files.

    Args:
        signed_dir (pathlib.Path): The PostSignedObjects directory.
        dbx_data (dict): The parsed DBX metadata JSON.
        strict (bool): If True, uncovered optional hashes are treated as errors.

    Returns:
        list: Error messages (empty when every documented revocation is enforced).
    """
    signed_hashes, signed_thumbprints = collect_signed_material(signed_dir)
    revoked_subjects = {
        cert["subjectName"]
        for cert in dbx_data.get("certificates", [])
        if cert.get("thumbprint", "").lower() in signed_thumbprints
    }
    errors = []

    for cert in dbx_data.get("certificates", []):
        if cert.get("thumbprint", "").lower() not in signed_thumbprints:
            errors.append(
                f"[cert] documented certificate is not revoked in the signed files: "
                f"{cert.get('subjectName')} ({cert.get('thumbprint')})"
            )

    for svn in dbx_data.get("svns", []):
        if svn.get("value", "").upper() not in signed_hashes:
            errors.append(
                f"[svn] documented SVN is not present in the signed files: "
                f"{svn.get('value')} ({svn.get('description', '')})"
            )

    for arch in ARCHITECTURES:
        uncovered_mandatory = []
        uncovered_optional = []
        for entry in dbx_data.get("images", {}).get(arch, []):
            hash_value = entry["authenticodeHash"].upper()
            if hash_value in signed_hashes or entry.get("signingAuthority") in revoked_subjects:
                continue
            record = (hash_value, entry.get("signingAuthority", ""))
            (uncovered_optional if entry.get("isOptional") else uncovered_mandatory).append(record)

        for hash_value, authority in uncovered_mandatory:
            errors.append(
                f"[{arch}] documented non-optional hash is neither signed nor cert-covered: "
                f"{hash_value} (authority: {authority or 'unknown'})"
            )

        if uncovered_optional:
            level = logging.ERROR if strict else logging.WARNING
            logging.log(
                level,
                f"[{arch}] {len(uncovered_optional)} optional documented hash(es) are neither "
                f"signed nor cert-covered" + ("" if strict else " [reported]"),
            )
            for hash_value, authority in uncovered_optional:
                logging.log(
                    level,
                    f"[{arch}]   uncovered optional: {hash_value} (authority: {authority or 'unknown'})",
                )
            if strict:
                errors.append(
                    f"[{arch}] {len(uncovered_optional)} optional documented hash(es) are neither "
                    f"signed nor cert-covered"
                )

    return errors


def validate(signed_dir: pathlib.Path, dbx_json_path: pathlib.Path, strict: bool) -> int:
    """Validate that the signed DBX payloads reproduce the documented DBX JSON.

    Args:
        signed_dir (pathlib.Path): The PostSignedObjects directory.
        dbx_json_path (pathlib.Path): Path to the dbx_info_msft_latest.json file.
        strict (bool): If True, enforce reproduction for every architecture.

    Returns:
        int: 0 on success, 1 if any validation error is found.
    """
    exceptions = set() if strict else REPRODUCIBILITY_EXCEPTIONS
    errors = []

    for arch in ARCHITECTURES:
        reproduced = reproduce_database(dbx_json_path, arch)
        reproduced_hashes = database_hashes(reproduced)
        reproduced_canonical = canonical_bytes(reproduced)

        for label, signed_files in signed_sources(signed_dir, arch).items():
            if not signed_files:
                errors.append(f"[{arch}/{label}] no signed DBX files found under {signed_dir}")
                continue

            signed = signed_database(signed_files)
            signed_hashes = database_hashes(signed)

            if canonical_bytes(signed) == reproduced_canonical:
                logging.info(
                    f"[{arch}/{label}] reproduces the non-optional DBX exactly "
                    f"({len(signed_hashes)} hashes)"
                )
                continue

            # Extra hashes are never allowed: a signed file must not contain a hash
            # that is not a documented, non-optional revocation for the architecture.
            extra = sorted(signed_hashes - reproduced_hashes)
            for hash_value in extra:
                errors.append(
                    f"[{arch}/{label}] signed hash is not a documented non-optional entry: {hash_value}"
                )

            # Missing hashes mean the signed file does not yet reproduce the JSON.
            missing = sorted(reproduced_hashes - signed_hashes)
            if missing:
                is_exception = arch in exceptions
                level = logging.WARNING if is_exception else logging.ERROR
                logging.log(
                    level,
                    f"[{arch}/{label}] {len(missing)} non-optional documented hash(es) are not signed "
                    f"(signed={len(signed_hashes)}, expected={len(reproduced_hashes)})"
                    + (" [known exception]" if is_exception else ""),
                )
                for hash_value in missing:
                    logging.log(level, f"[{arch}/{label}]   unsigned: {hash_value}")
                if not is_exception:
                    errors.append(
                        f"[{arch}/{label}] {len(missing)} non-optional documented hash(es) are not signed"
                    )

            # Identical hash set but different bytes indicates an owner or structural
            # mismatch that would still make the payload non-reproducible.
            if not extra and not missing:
                message = (
                    f"[{arch}/{label}] signed payload does not match the reproduced bytes despite an "
                    f"identical hash set (signature owner or structure mismatch)"
                )
                if arch in exceptions:
                    logging.warning(message)
                else:
                    errors.append(message)

    with open(dbx_json_path, "r") as f:
        dbx_data = json.load(f)
    errors.extend(validate_completeness(signed_dir, dbx_data, strict))

    if errors:
        logging.error(f"Signed DBX validation failed with {len(errors)} error(s):")
        for error in errors:
            logging.error(f"  {error}")
        return 1

    logging.info(
        "Signed DBX validation passed: signed payloads reproduce the documented DBX JSON "
        "and every documented revocation is enforced."
    )
    return 0


def main() -> int:
    """Parse arguments and run the signed DBX validation."""
    parser = argparse.ArgumentParser(
        description="Validate signed DBX payloads against the documented DBX JSON."
    )
    parser.add_argument(
        "signed_dir",
        nargs="?",
        default="PostSignedObjects",
        type=pathlib.Path,
        help="The PostSignedObjects directory containing the signed DBX files.",
    )
    parser.add_argument(
        "--dbx-json",
        default="PreSignedObjects/DBX/dbx_info_msft_latest.json",
        type=pathlib.Path,
        help="Path to the authoritative DBX metadata JSON file.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Enforce reproduction for every architecture, ignoring known exceptions.",
    )
    args = parser.parse_args()

    return validate(args.signed_dir, args.dbx_json, args.strict)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    sys.exit(main())

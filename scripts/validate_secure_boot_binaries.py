import argparse
import json
import pathlib
import struct
from dataclasses import dataclass
from uuid import UUID

from edk2toollib.uefi.authenticated_variables_structure_support import (
    EfiSignatureDatabase,
    EfiSignatureDataEfiCertSha256,
    EfiSignatureDataEfiCertX509,
    EfiVariableAuthentication2,
)
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1_modules import rfc2315

try:
    import tomli as tomllib
except Exception:
    import tomllib
import logging

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# Console handler with colored logs
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
try:
    import coloredlogs

    coloredlogs.install(level="DEBUG", logger=logger, fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
except ImportError:
    console_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    logger.addHandler(console_handler)

# File handler
file_handler = logging.FileHandler("secure_boot_validation.log")
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
logger.addHandler(file_handler)

# All SVNs will have this as the "signature_owner" and then map to a per app guid in the hash field
SVN_OWNER_GUID = svn_guid = UUID("9d132b6c-59d5-4388-ab1c-185cfcb2eb92")


@dataclass
class BootAppSvn:
    MajorSvn: int
    MinorSvn: int

    @property
    def AsUInt32(self):
        return (self.MajorSvn << 16) | self.MinorSvn

    @classmethod
    def from_uint32(cls, value):
        minor_svn = value & 0xFFFF
        major_svn = (value >> 16) & 0xFFFF
        return cls(MinorSvn=minor_svn, MajorSvn=major_svn)


@dataclass
class SvnData:
    Version: int
    ApplicationGuid: UUID
    Svn: BootAppSvn
    Reserved: bytes

    @classmethod
    def from_bytes(cls, data):
        (version,) = struct.unpack_from("B", data, 0)
        application_guid = UUID(bytes_le=data[1:17])
        (svn_value,) = struct.unpack_from("I", data, 17)
        svn = BootAppSvn.from_uint32(svn_value)
        reserved = data[21:32]
        return cls(Version=version, ApplicationGuid=application_guid, Svn=svn, Reserved=reserved)

    def to_bytes(self):
        data = struct.pack("B", self.Version)
        data += self.ApplicationGuid.bytes
        data += struct.pack("I", self.Svn.AsUInt32)
        data += self.Reserved
        return data


def get_signers(auth_var) -> list:
    """Get the signer from the authenticated variable."""
    # Technically there can be multiple SignerInfos, but in general there is only one
    signer_info_records = []

    asn1_signed_Data, _ = der_decode(auth_var.auth_info.cert_data, asn1Spec=rfc2315.SignedData())
    # Access the SignerInfos
    signer_infos = asn1_signed_Data.getComponentByName("signerInfos")

    # Iterate through each SignerInfo
    for signer_info in signer_infos:
        retrieved_signer_info = {}
        signer_identifier = signer_info.getComponentByName("issuerAndSerialNumber")
        issuer = signer_identifier.getComponentByName("issuer")
        for rdn in issuer[0]:
            for attribute in rdn:
                attribute_type = str(attribute.getComponentByName("type"))
                # Remove non-printable characters and the first character which is a `!`
                attribute_value = "".join(ch for ch in str(attribute.getComponentByName("value")) if ch.isprintable())[
                    1:
                ]
                retrieved_signer_info.update({attribute_type: attribute_value})

        signer_info_records.append(retrieved_signer_info)

    return signer_info_records


def _validate_signer(signer_info: list, expected_signer: str, save_file=None) -> bool:
    """Validate the signer of the authenticated variable."""
    logger.info("Validating signer")

    if len(signer_info) > 1:
        # This may change in the future but today we only expect one signer
        logger.error(f"Expected only one signer. Found {len(signer_info)}")
        raise ValueError(f"Expected only one signer. Found {len(signer_info)}")

    signer = signer_info[0].get("2.5.4.3")
    if expected_signer not in signer:
        logger.error(f"Signer {signer} does not match expected signer {expected_signer}")
        raise ValueError(f"Signer {signer} does not match expected signer {expected_signer}")
    logger.info(f"Signer matches expected signer ({signer})")

    if save_file:
        with open(save_file, "w") as f:
            f.write(signer_info)

    return True


def _validate_signature_list(signature_database: EfiSignatureDatabase, dbx_data: dict, save_file=None) -> None:
    if save_file:
        with open(save_file, "w") as f:
            logger.debug(f"Writing signature database to {save_file}")
            signature_database.print(outfs=f)

    expected_svns = dbx_data.get("svns")

    for signature in signature_database.esl_list:
        for a in signature.signature_data_list:
            if type(a) == EfiSignatureDataEfiCertSha256:
                # Validate SVNs
                if a.signature_owner == SVN_OWNER_GUID:
                    for svn in expected_svns:
                        guid = svn.get("svnAppGuid")
                        parsed_svn_data = SvnData.from_bytes(a.signature_data)
                        expected_svn_data = SvnData.from_bytes(bytes.fromhex(svn.get("value")))

                        # If the guid in the binary maps to the guid in the file - we found our match
                        if str(parsed_svn_data.ApplicationGuid) in guid:
                            # Now we can compare the svn_data
                            if parsed_svn_data != expected_svn_data:
                                logger.error(
                                    f"SVN data mismatch for {guid}: expected {expected_svn_data}, got {parsed_svn_data}"
                                )
                                raise ValueError(
                                    f"SVN data mismatch for {guid}: expected {expected_svn_data}, got {parsed_svn_data}"
                                )

                            logger.info(f'Found "{guid}" with {parsed_svn_data.Svn}')
                            break

            elif type(a) == EfiSignatureDataEfiCertX509:
                pass


def validate_dbx(dbx: dict, output: str) -> bool:
    """Validate the DBX file."""
    logger.debug("Validating DBX files")
    # Load the latest DBX file
    latest_documented_dbx = dbx.get("latest_dbx")
    if not latest_documented_dbx:
        logger.error("No latest documented DBX file provided.")
        return False

    # Load the DBX file
    dbx_data = None
    with open(latest_documented_dbx, "rb") as dbx_file:
        dbx_data = json.load(dbx_file)

    # Check if the DBX file is empty
    if not dbx_data:
        logger.error("The DBX file is empty.")
        return False

    for section in dbx:
        #
        # General or Optional
        #
        if type(dbx[section]) is list:
            output_dir = pathlib.Path(output) / section
            if not output_dir.exists():
                logger.info(f"Creating output directory for section {section} at {output_dir}")
                output_dir.mkdir(parents=True, exist_ok=True)

            for dbx_file in dbx[section]:
                for file in dbx_file.get("files"):
                    logger.info(f"Loading DBX file {file.get('path')}")
                    with open(file.get("path"), "rb") as dbx_file:
                        auth_var = EfiVariableAuthentication2(decodefs=dbx_file)
                        # Get the signer information, the purpose of this is to validate the signer and ensure that the wrong
                        # signer was not used

                        section_name = pathlib.Path(file.get("path")).parts[-3]
                        arch_name = pathlib.Path(file.get("path")).parts[-2]
                        basename = pathlib.Path(file.get("path")).stem

                        signer_file = None
                        if section_name == section:
                            arch_dir = output_dir / arch_name
                            if not arch_dir.exists():
                                logger.info(f"Creating architecture directory {arch_dir}")
                                arch_dir.mkdir(parents=True, exist_ok=True)

                            signer_file = arch_dir / f"{basename}.signer.txt"

                        signer_info = get_signers(auth_var)
                        _validate_signer(signer_info, file.get("signer"), save_file=signer_file)

                        # TODO create a function that performs the authenticode validation
                        _validate_signature_list(auth_var.sig_list_payload, dbx_data)

                        logger.info(f"Successfully validated: {file.get('path')}")
        else:
            # Informational
            pass

    return True


def validate(keystore: dict, output: str) -> bool:
    validation_handlers = {
        "DBX": validate_dbx,
    }

    for keys in keystore:
        if keys not in validation_handlers:
            logger.error(f"Unknown key {keys} in keystore.")
            return False

        validator = validation_handlers[keys]
        if not validator(keystore[keys], output):
            logger.error(f"Validation failed for {keys}.")
            return False


def load_keystore(keystore: pathlib.Path) -> dict:
    """Load the keystore from a file."""
    if not keystore.exists():
        logger.error(f"Keystore file {keystore} does not exist.")
        raise FileNotFoundError(f"Keystore file {keystore} does not exist.")

    with open(keystore, "rb") as keystore_file:
        keystore_data = tomllib.load(keystore_file)

    return keystore_data


def main() -> int:
    """Main entry point into the tool."""
    parser = argparse.ArgumentParser(description="Build the default keys for secure boot.")
    parser.add_argument(
        "--keystore",
        help="A json file containing the keys mapped to certificates and hashes.",
        default="OsDefaults.toml",
        required=True,
    )
    parser.add_argument(
        "-o",
        "--output",
        type=pathlib.Path,
        default=pathlib.Path.cwd() / "Artifacts",
        help="The output directory for the default keys.",
    )

    args = parser.parse_args()

    keystore = load_keystore(pathlib.Path(args.keystore))

    if not args.output.exists():
        logger.info(f"Creating output directory at {args.output}")
        args.output.mkdir(parents=True, exist_ok=True)

    validate(keystore, output=args.output)


if __name__ == "__main__":
    main()

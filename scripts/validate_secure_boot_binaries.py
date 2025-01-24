import argparse
import json
import pathlib

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

level = "DEBUG"
try:
    import coloredlogs

    # To enable debugging set level to 'DEBUG'
    coloredlogs.install(level=level, logger=logger, fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
except ImportError:
    logging.basicConfig(level=level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")




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
    logger.info("Test: Validating signer")

    if len(signer_info) > 1:
        # This may change in the future but today we only expect one signer
        raise ValueError(f"Expected only one signer. Found {len(signer_info)}")

    signer = signer_info[0].get("2.5.4.3")
    logger.info(f"\tBinary signer: {signer}")
    logger.info(f"\tExpected signer: {expected_signer}")
    if expected_signer not in signer:
        raise ValueError(f"Signer {signer} does not match expected signer {expected_signer}")
    logger.info('\tResult: Signer matches expected signer')

    if save_file:
        with open (save_file, "w") as f:
            f.write(signer_info)

    return True

def _validate_signature_list(signature_database: EfiSignatureDatabase, dbx_data: dict, save_file=None) -> None:
    if save_file:
        with open(save_file, "w") as f:
            logger.debug(f"Writing signature database to {save_file}")
            signature_database.print(outfs=f)

    for signature in signature_database.esl_list:
        for a in signature.signature_data_list:
            if type(a) == EfiSignatureDataEfiCertSha256:

                # Check if the guid belongs to a SVN
                for svn in dbx_data.get("svns"):
                    guid = svn.get("guid")
                    print(a.signature_owner)
                    print(guid)
                    if str(a.signature_owner) in guid:
                        logger.info(f"Signature owner {a.signature_owner} is in the DBX file.")
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

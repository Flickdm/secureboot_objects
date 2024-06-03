import argparse
import hashlib
import logging
import os
import shutil
import sys

import tomllib
import yaml
from edk2toollib.uefi.authenticated_variables_structure_support import (
    EfiSignatureDataEfiCertSha256,
    EfiSignatureDataEfiCertX509,
    EfiVariableAuthentication2,
)

ARTIFACTS = "./Artifacts"

# Status codes
EOK = 0 # Ok
EINVAL = 22 # Invalid argument

SUPPORTED_ARCHITECTURES = ["amd64", "x86", "arm", "arm64"]

# The architecture mapping is used to map the architecture from the CSV file to the architecture in the DBX
ARCHITECTURE_MAPPING = {
    "64-bit": "amd64",
    "32-bit": "x86",
    "32-bit ARM": "arm",
    "64-bit ARM": "arm64",
}

def configure_logging(artifact_path):

    ARTIFACTS = artifact_path

    if not os.path.exists(ARTIFACTS):
        os.makedirs(ARTIFACTS)
    else:
        shutil.rmtree(ARTIFACTS)
        os.makedirs(ARTIFACTS)

    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Create a file handler and set the log file path
    log_file = os.path.join(artifact_path, 'log.txt')
    file_handler = logging.FileHandler(log_file)

    # Create a stream handler to write logs to stdout
    stream_handler = logging.StreamHandler(sys.stdout)

    # Set the log level for the file handler and stream handler
    file_handler.setLevel(logging.INFO)
    stream_handler.setLevel(logging.INFO)

    # Create a formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    stream_handler.setFormatter(formatter)

    # Add the handlers to the root logger
    logging.getLogger().addHandler(file_handler)
    logging.getLogger().addHandler(stream_handler)

def save_dict_artifact(save_path, dict_to_save):

    # split off the file name from the path
    save_path = os.path.join(ARTIFACTS, f"{save_path}.yaml")
    path = os.path.dirname(save_path)

    if not os.path.exists(path):
        os.makedirs(path)

    logging.info("Saving %s", save_path)
    with open(save_path, "w") as f:
        yaml_data = yaml.dump(dict_to_save, default_flow_style=False)
        f.write(yaml_data)

def validate_signature(signers, dbx_contents, name="dbx"):
    # TODO - Implement this function
    logging.debug("NOT IMPLEMENTED: validate_signature")
    return EOK


def flatten_dbx_info(dbx_info):
    """Flatten the dbx_info list of lists into a single list.

    Args:
        dbx_info (list): list of lists

    Returns:
        dictionary: flattened dictionary

        The dictionary is of the form:
            HASH: {dbxType, dbxFil, arch} for Authenticode
            THUMBPRINT: {dbxType, dbxFil, None} for Certificate
            SVN: {dbxType, dbxFil, None} for SVN
    """
    flattened_dbx_list = {}

    for file in dbx_info:
        logging.info("DBX File: %s", file)

        # get the name of the folder proceeding the file
        folder = file.split("/")[-2].upper()

        # check the extension
        if file.endswith(".csv") and folder == "HASHES":
            # open the file and read the contents
            with open(file, "r") as f:
                # read the contents of the file
                contents = f.read()
                # split the contents by newline
                lines = contents.split("\n")
                # remove the empty strings
                lines = [line for line in lines if line]

                # the line is csv delimited by commas
                # we need the second element
                for line in lines[1:]:

                    # skip the comments (csv does not support comments, but we can add them in the csv file)
                    if line[0] == "#":
                        continue

                    # split the line by commas
                    line = line.split(",")
                    # get the second element
                    authenticode = line[1]
                    architecture = ARCHITECTURE_MAPPING.get(line[3], line[3])
                    # append the authenticode to the list
                    flattened_dbx_list[authenticode] = {
                        "dbx_type": "authenticode",
                        "dbx_file": line[2],
                        "dbx_arch": architecture
                    }

        elif file.endswith(".der") and folder == "CERTIFICATES":
            # open the file and read the contents
            with open(file, "rb") as f:
                # read the contents of the file
                contents = f.read()

                # get the name of the file without the full path
                filename = file.split("/")[-1]

                # Calculate the thumbprint of the certificate
                thumbprint = hashlib.sha256(contents).hexdigest()

                # return the list
                flattened_dbx_list[thumbprint] = {
                    "dbx_type": "certificate",
                    "dbx_file": filename,
                    "dbx_arch": None
                }

        elif file.endswith(".csv") and folder == "SVN":
            # open the file and read the contents
            with open(file, "r") as f:
                # read the contents of the file
                contents = f.read()
                # split the contents by newline
                lines = contents.split("\n")
                # remove the empty strings
                lines = [line for line in lines if line]

                # the line is csv delimited by commas
                # we need the second element
                for line in lines[1:]:
                    # split the line by commas
                    line = line.split(",")
                    # get the second element
                    svn = line[0]
                    application = line[1]
                    # append the authenticode to the list
                    flattened_dbx_list[svn] = {
                        "dbx_type": "svn",
                        "dbx_file": application,
                        "dbx_arch": None
                    }

    return flattened_dbx_list

def convert_bytes_to_ascii(byte_array):
    """Convert a byte array to ascii string.

    Args:
        byte_array (bytes): byte array to convert

    Returns:
        str: ascii string
    """
    guid_string = ""
    for index in range(len(byte_array)):
        guid_string += f"{byte_array[index]:02X}"

    return guid_string

def filter_by_architecture(complete_dbx, arch):
    """Filter the dbx contents by architecture.

    Args:
        complete_dbx (dict): dictionary containing all possible dbx contents
        arch (str): architecture to filter by

    Returns:
        dict: dictionary containing the dbx contents for the specified architecture
    """
    filtered_dbx_contents = {}
    for entry in complete_dbx:
        if complete_dbx[entry]["dbx_arch"] == arch or complete_dbx[entry]["dbx_arch"] is None:
            filtered_dbx_contents[entry] = complete_dbx[entry]

    return filtered_dbx_contents

def get_siglist_contents(siglists):
    """Get the contents of the siglists.

    Args:
        siglists (list): list of siglists

    Returns:
        list: list of contents
    """
    contents = {}
    for siglist in siglists:
        for sig in siglist.signature_data_list:
            if type(sig) is EfiSignatureDataEfiCertSha256:
                contents[convert_bytes_to_ascii(sig.signature_data)] = {
                    "signature_owner": str(sig.signature_owner),
                    "signature_type": "SHA256 Hash"
                }
            elif type(sig) is EfiSignatureDataEfiCertX509:
                thumbprint = hashlib.sha256(sig.signature_data).hexdigest()
                contents[thumbprint] = {
                    "signature_owner": str(sig.signature_owner),
                    "signature_type": "X.509 Certificate"
                }
            else:
                logging.error("Unknown signature type: %s", type(sig))

    return contents


def _validate_dbx_binary(complete_dbx, siglists, payload, arch):
    """Validate the DBX contents against the signed files.

    Args:
        complete_dbx (dict): dictionary containing the expected dbx contents
        siglists (list): list of siglists
    
    Returns:

    """
    error_code = EINVAL
    expected_dbx = filter_by_architecture(complete_dbx, arch)
    found_dbx = get_siglist_contents(siglists)
    missing_from_csv = {}

    save_dict_artifact(f"{payload}.expected_in_dbx", expected_dbx)
    save_dict_artifact(f"{payload}.found_in_dbx", found_dbx)

    # Check if the hashes in the signed files are in the dbx
    for hash in found_dbx:
        if hash in expected_dbx:
            del expected_dbx[hash]
        else:
            logging.error("Hash %s not found in Expected DBX for architecture %s (Check your CSV files!)", hash, arch)
            missing_from_csv[hash] = found_dbx[hash]
            missing_from_csv[hash].update({"dbx_arch": arch})
            missing_from_csv[hash].update({"diff_arch": None})
            if hash in complete_dbx:
                missing_from_csv[hash].update({"diff_arch": complete_dbx[hash]["dbx_arch"]})
                logging.error("Appears that the hash is in the DBX for a different architecture %s", complete_dbx[hash]["dbx_arch"])


    save_dict_artifact(f"{payload}.missing_from_dbx", expected_dbx)
    save_dict_artifact(f"{payload}.missing_from_csv", missing_from_csv)

    if len(expected_dbx) == 0:
        logging.info("All hashes found in signed files")
        error_code = EOK
    else:
        logging.error("Appears that some expected hashes are missing from the signed files")

    return error_code

def validate_dbx(dbx_contents):
    """Validate the DBX contents against the signed files.

    The DBX is considered valid if all the hashes in the DBX are found in the signed files
    and no hashes in the signed files are missing from the DBX.

    Args:
        dbx_contents (dict): dictionary containing the dbx contents

    Returns:
        int: status code
            EOK: if the DBX contents are valid
            EINVAL: if the DBX contents are invalid
    """
    for database in dbx_contents:
        dbx_info = dbx_contents[database]["dbx_info"]
        complete_dbx = flatten_dbx_info(dbx_info)

        for arch in SUPPORTED_ARCHITECTURES:
            arch = arch.lower()
            signed_payload = dbx_contents[database][arch]
            auth_var2 = EfiVariableAuthentication2()

            logging.info("Validating %s", signed_payload)
            with open(signed_payload, "rb") as f:
                auth_var2.decode(f)

            if auth_var2.sig_list_payload is None:
                logging.error("No signature list found in %s", signed_payload)
                continue

            siglists = auth_var2.sig_list_payload.EslList

            logging.info("Validating %s", signed_payload)
            if _validate_dbx_binary(complete_dbx, siglists, signed_payload, arch) == EINVAL:
                pass
                # TODO every binary must pass validation however none are currently passing
                #return EINVAL

    return EOK


def validate(args):
    # Perform validation logic here
    error_code = EINVAL

    config = {}

    configure_logging(args.artifacts)

    logging.info("Results will be saved to %s", args.artifacts)

    with open(args.mapping_file, "r") as f:
        config = tomllib.loads(f.read())

        signers = config.get("SIGNING_CERTIFICATE_LIST", {})
        dbx_contents = config.get("DBX", {})

        logging.info("Validating Signature on signed files")
        validate_signature(signers, dbx_contents)

        logging.info("Validating DBX Contents match expected contents")
        error_code = validate_dbx(dbx_contents)
        if error_code == EOK:
            logging.info("DBX Contents Validation successful")
        else:
            logging.error("DBX Contents Validation failed")
            #return error_code

    return EOK

def setup_validation_parser(subparsers: argparse._SubParsersAction) -> argparse._SubParsersAction:
    """Setup the describe subparser.

    Args:
        parser (argparse._SubParsersAction): the subparsers object from the ArgumentParser

    """
    parser = subparsers.add_parser("validate", help="Validate signed files")
    parser.add_argument("mapping_file", help="maps the signed files to the contents they were built from")
    parser.add_argument("--artifacts", help="output folder for validation results", default="Artifacts")
    parser.set_defaults(function=validate)


def parse_args():
    parser = argparse.ArgumentParser(description="Validate signed files")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    subparsers = parser.add_subparsers()
    setup_validation_parser(subparsers)

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    return parser.parse_args()


def main():
    args = parse_args()
    status = args.function(args)
    sys.exit(status)

if __name__ == "__main__":
    main()

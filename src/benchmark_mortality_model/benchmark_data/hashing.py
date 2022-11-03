import pathlib
import hashlib
import os

import pandas as pd


def update_hash():
    os.remove("FileHashes.csv")
    p = pathlib.Path().absolute()
    hash_df = pd.DataFrame(columns=["FilePath", "sha256"])

    for f in p.glob('**/*.csv'):
        hash_df = hash_df.append({"FilePath": pathlib.Path(f).relative_to(p).as_posix(), "sha256": compute_sha256(str(f))}, ignore_index=True)

    hash_df.to_csv("FileHashes.csv", index=False)


def check_hash():
    hash_df = pd.read_csv(pathlib.Path(__file__).parent.joinpath("FileHashes.csv"))

    for index, row in hash_df.iterrows():
        actual_sha256 = compute_sha256(str(pathlib.Path(__file__).parent.joinpath(row["FilePath"]).as_posix()))
        expected_sha256 = row["sha256"]

        if not actual_sha256 == expected_sha256:
            raise ValueError(f"File '{row['FilePath']}' hash error. Expected {expected_sha256}, got {actual_sha256}.")


def compute_sha256(file_name):
    """
    Compute the SHA256 hash of a file.
    
    :param file_name: Absolute or relative pathname of the file that shall be parsed.
    :return: Resulting SHA256 hash.
    """
    # Set the SHA256 hashing
    hash_sha256 = hashlib.sha256()

    # Open the file in binary mode (read-only) and parse it in 65,536 byte chunks (in case of
    # large files, the loading will not exceed the usable RAM)
    with pathlib.Path(file_name).open(mode="rb") as f_temp:
        for _seq in iter(lambda: f_temp.read(65536), b""):
            hash_sha256.update(_seq)

    # Digest the SHA256 result
    sha256_res = hash_sha256.hexdigest()

    return sha256_res


if __name__ == "__main__":
    update_hash()
    check_hash()

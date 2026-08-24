# System Architecture

## The Execution Pipeline
The pipeline follows a strict sequence: Target directories are compressed into unencrypted tarballs. The data is loaded into memory, encrypted via the IPC bridge command, and output as `.obv` and `.obk` files. The temporary unencrypted archive is immediately unlinked and deleted from the filesystem to ensure operational security.
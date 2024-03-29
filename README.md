# procview

Process Viewer. Use this to easily check whether there are any suspicious processes or processes accessing a suspicious destination.

## Installation

None

## Usage
    usage: procview.py [-h] [-v] [--bin] [--network]

    optional arguments:
      -h, --help     show this help message and exit
      -v, --verbose
      --bin
      --network

## Example
### list
    > python .\procview.py
    name, pid
    ----
    Calculator, 5792
    cmd, 11364
    Code, 2212
    .
    .
    .
    .

### detail
    > python .\procview.py -v
    ----
    Name                          : cmd
    Id                            : 11364
    PriorityClass                 : Normal
    FileVersion                   : 10.0.18362.1 (WinBuild.160101.0800)
    HandleCount                   : 77
    WorkingSet                    : 4026368
    .
    .
    .
    .

### bin file
    > python .\procview.py --bin
    ----
    path                          : C:\Program Files\Microsoft VS Code\Code.exe
    size                          : 92159864
    hash_vals(md5)                : 87c77562db764ea4b915cc0f3594ead7
    hash_vals(sha1)               : da39a3ee5e6b4b0d3255bfef95601890afd80709
    hash_vals(sha256)             : e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    hash_vals(sha512)             : cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
    timestamp_vals(ctime)         : 2019-09-13 10:13:45
    timestamp_vals(mtime)         : 2019-09-11 13:47:00
    timestamp_vals(atime)         : 2019-09-13 10:13:48
    verified_signer(signer)       : Microsoft Corporation
    verified_signer(status)       : Valid
    ----
    .
    .
    .

### network
    > python .\procview.py --network
    name                pid       proto             local                         remote             state
    ------------------------------------------------------------------------------------------------------------------
    Code                2256      TCP             127.0.0.1:31527                  0.0.0.0:0         LISTENING
    Code                11844     TCP          192.168.???.???:50432       ???.???.???.???:443       ESTABLISHED
    SearchUI            9532      TCP          192.168.???.???:50326       ???.???.???.???:443       ESTABLISHED
    .
    .
    .
    .


## Requirement

- python 3.6 or more
- Windows users who do not use python should use procview.exe in the bin directory.

## Author

[abwo](https://github.com/abwo)



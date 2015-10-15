# p11speed

p11speed is part of the SoftHSM project, but can be used with other HSMs.

## Introduction

This program is made to benchmark the performance of PKCS#11 enabled devices.
PKCS#11 specifies how to communicate with cryptographic devices such as
HSM:s (Hardware Security Modules) and smart cards. The purpose of these devices
is, among others, to generate cryptographic keys and sign information without
revealing private-key material to the outside world. They are often designed to
perform well on these specific tasks compared to ordinary processes in a normal
computer.

## Developers

- Rickard Bellgrim (Knowit Secure AB, www.knowitgroup.com)

## Dependencies

The program loads the PKCS#11 library by using 'libdl' and the cryptographic
operations are run in different threads using 'libpthread'.

## Installation

### Building from the repository

If the code is downloaded directly from the code repository, you have to
prepare the configuration scripts before running it.

1. You need to install automake, autoconf, libtool, etc.
2. Run the command 'sh autogen.sh'

### Configure

Configure the installation/compilation scripts:

	./configure

For more options:

	./configure --help

### Compile

Compile the source code using the following command:

	make

### Install

Install the program using the follow command:

	sudo make install

## Using p11speed

p11speed will load the SoftHSMv2 library by default,
but can be adjusted to use another library.

	p11speed --module <path>

Most HSMs will be utilized better when running with multiple threads (--threads).
Increasing the number of iterations per thread (--iterations) will also boost the
performance.

The PIN is optional on the command line, but will be prompted for.

### List slots

All the available slots and their current status can be listed using this command:

	p11speed --show-slots

### Signature operations

Benchmark the performance of signature operation using C_SignInit() and
C_Sign(). The signatures are created using pre-defined hash values.

A temporary key with a given key size will be generated. Note that GOST has a
fixed key size and that ECDSA has two supported curves, P-256 and P-384. In the
case of ECDSA, use 256 or 384 as the key size.

	p11speed --sign --slot <number> [--pin <PIN>] --mechanism <name>
		[--keysize <bits>] --threads <number> --iterations <number>

Available mechanisms and their key size:

- RSA_PKCS (1024 - 4096)
- DSA (1024 - 4096)
- ECDSA (256, 384)
- GOSTR3410

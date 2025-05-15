# Foofus.net ~ Medusa

**Medusa Parallel Network Login Auditor**

Copyright (C) 2024 Joe Mondloch<br />
JoMo-Kun / jmk@foofus.net

Medusa is a speedy, parallel, and modular, login brute-forcer. The goal is to support as many services which allow remote authentication as possible. The author considers the following items as some of the key features of this application:

- Thread-based parallel testing. Brute-force testing can be performed against multiple hosts, users or passwords concurrently.

- Flexible user input. Target information (host/user/password) can be specified in a variety of ways. For example, each item can be either a single entry or a file containing multiple entries. Additionally, a combination file format allows the user to refine their target listing.

- Modular design. Each service module exists as an independent .mod file. This means that no modifications are necessary to the core application in order to extend the supported list of services for brute-forcing.

- Multiple protocols supported. Many services are currently supported (e.g. SMB [SMBv1-3 w/ SMB signing], HTTP, MS-SQL, POP3, RDP, SSHv2, among others).

Documentation: https://jmk-foofus.github.io/medusa/medusa.html

-----

## Installation Steps:
## 1. Clone the repository

```bash
git clone {URL}
cd medusa
```

## 2. Prepare the build system

```bash
autoreconf -fi
```

## 3. Install dependencies

Make sure you have essential build tools and OpenSSL installed:

```bash
brew install automake autoconf libtool pkg-config openssl
```

## 4. Configure with OpenSSL path

macOS’s OpenSSL headers are not in standard system locations. Get the OpenSSL prefix:

```bash
OPENSSL_DIR=$(brew --prefix openssl@3)
```

Run `configure` explicitly specifying OpenSSL location:

```bash
./configure --with-ssl=$OPENSSL_DIR
```

## 5. Compile

```bash
make
```

## 6. Install

```bash
sudo make install
```

---


### Notes:

- If you get the error:

  ```
  configure: error: *** OpenSSL header files required for SSL support. ***
  ```

  It means the OpenSSL development headers are missing or not found. Step 4 fixes this by pointing `configure` to Homebrew's OpenSSL installation.

- On Apple Silicon Macs, OpenSSL is usually in `/opt/homebrew/opt/openssl@3`

- On Intel Macs, OpenSSL is usually in `/usr/local/opt/openssl@3`

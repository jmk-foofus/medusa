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

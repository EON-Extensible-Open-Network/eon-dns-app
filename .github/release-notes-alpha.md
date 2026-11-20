**EON DNS** encrypts every name lookup your computer makes. It sends them to the
resolvers you choose, checks DNSSEC signatures here, and blocks malware, ads or adult
sites on this computer, showing why each one was blocked. One switch turns it on. Free,
open source, no account, no telemetry.

**Early alpha:** for trying out. Windows can be switched over to it by the program; on
Linux and macOS the resolver runs on 127.0.0.1, and pointing the system at it is a manual
step for now.

**Install:** download the file for your system and run it. Turning protection on asks
Windows for permission once, to point your DNS at EON DNS, and EON DNS writes down what
was there before. Turning it off, or quitting, puts that back.

**Not signed:** EON has no signing keys yet (plan, madde 30 and 34). Check the files
against `SHA256SUMS.txt`. On Windows, Smart App Control (if on) refuses unsigned
downloads.

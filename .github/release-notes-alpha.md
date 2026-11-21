**EON DNS** is one switch for two jobs.

**Lookups.** Every name lookup is encrypted to resolvers you choose. Malware, ads or adult
sites are blocked on your computer, and each block shows why.

**The tunnel.** Choose WARP, your own WireGuard server, or an EON server, and *all* your
traffic goes through it, sealed. It works like Cloudflare's WARP, including for sites that
are blocked by name.

It is free and open source, with no account and no telemetry.

**Early alpha:** for trying out, on Windows. On Linux and macOS the resolver runs on
`127.0.0.1`; the tunnel and switching the system over come later.

**Install:** download the file and run it. The first time you press the switch, Windows
asks once to set up the EON DNS service, which keeps protection on in the background and
puts your DNS settings back when it stops. After that, the switch asks nothing.

**Not signed:** EON has no signing keys yet (plan madde 30 and 34). Check the files against
`SHA256SUMS.txt`. On Windows, Smart App Control (if it is on) refuses unsigned downloads.

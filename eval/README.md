To re-run the measurements two machines are needed that are connected with a 10G card.
Both have exactly the same configuration but one functions as client and one as server.
They need netmap loaded as kernel module and the netmap binaries built in the 'netmap' folder in the home directory.

The Makefile has some rules defined for gathering the data and genarating graphs but manual work is still needed.
First replace `support@10.0.3.1` for the client and `support@10.0.3.2` for the server in all files with the login and IP of your client and server systems.
Use, e.g., this command to change the client to `LOGIN@SYSTEM`:

    $ rg 'support@10.0.3.1' --files-with-matches -0 | xargs -0 sed -i 's/support@10.0.3.1/LOGIN@SYSTEM/g'

Also you need to change the servers internal IP of the 10G card if it is not `169.254.137.191`.
The names of the interfaces also need to be adjusted from `enp4s0f0` for the client and `enp6s0f0` for the server (you also would rename the `IFNAMEconfig` files in this folder here).
The group ID of the user is expected to be `1000`, otherwise adjust the `ALLOW_GID` entry in the `IFNAMEconfig` files.

Please make sure that the kernel does not use offloading (but still the comparison of kernel network stack and userspace is not too meaningful) and also that Ethernet flow control is disabled.

    # ethtool -K enp1s0f0 tx off rx off gso off tso off gro off # maybe also "lro off"
    # ethtool --pause enp1s0f0 tx off rx off

Afterwards, upload the test binaries to the two systems:

    make upload

Now run the tests, and enter the user password of the test machines to enter sudo mode if requested:

    make tests

Unfortunately the smolbench utility does not yet include measuring packets per seconds and parallel HTTP requests per second.
Therefore, the measurement relies on running `pkt-gen` and `/usr/bin/ab` manually as described in:

    make manualtestmpps
    make manualtesthttp

Now all experiment folders should contain the results for the last run in the `EXPERIMENTFOLDER/last` file.

Finally, generate the graphs (needs the altair Python library installed and Inkscape for PDF generation):

    make generategraphs

The results are now in the folder graphs/ as SVG and PDF files.

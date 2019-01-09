The smolbench program has serveral modes.

Build with `cargo build --release` and run the resulting binary to see the invokation arguments:

    $ target/release/smolbench -h

Via subcommands the following modes are available:

    client     Run in client mode (via Linux host if not --api, otherwise env USNET_SOCKETS config)
    crawl      Fetch HTTP (USNET_SOCKETS backend config)
    httpd      Serve HTTP (USNET_SOCKETS backend config)
    server     Run in Linux socket server mode (default)
    smoltcp    Run in smoltcp server (env var USNET_SOCKETS config)

Use the `help client|crawl|httpd|server|smoltcp` subcommand to see more.

The client submode can either use the Linux host stack (no argument), smoltcp (`--smoltcp-no-api`), or usnet_sockets (`--api`). The smoltcp mode runs the server with either smoltcp (no argument) or usnet_sockets (`--api`). The server mode uses just the Linux kernel stack.
The crawl submode uses smoltcp (`--smoltcp-no-api`) or usnet_sockets (no argument). The httpd mode uses usnet_sockets.

This build always uses the usnet_sockets with a multithread-capable API in the submodes `httpd`, `crawl`, and the `client|smoltcp` modes (with `--api`).
When compiled differently, the used API can be adjusted as follows.

A simple singlethread-constrained API is also supported for evaluation of the overhead. Compile as:

    $ cargo build --release --features single --no-default-features

To not use the usnet_sockets library, compile as:

    $ cargo build --release --features host --no-default-features

The evaluation scripts may serve as examples how to use the binary.

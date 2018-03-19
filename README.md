# mapbtc

## Introduction

mapbtc is a C program which maps out the Bitcoin peer-to-peer network.

It uses Linux epoll(2) and non-blocking sockets to communicate with peer nodes asynchronosly thus accelerating the mapping process.

## Usage

To build and run mapbtc:
1. Install build tools and development package for OpenSSL, e.g. on Fedora `sudo dnf install gcc make openssl-devel`.
2. Build mapbtc by typing `make` in it's directory.
3. Run mapbtc simply with `./mapbtc`, and it will begin mapping out the Bitcoin network.

When mapbtc finishes, it will have created two files, `peers.csv`, which contains a CSV of discovered peers with some additional information about them and also `peers_graph.csv` which contains a CSV table of connections between the discovered peers.

You can interrupt mapbtc at any moment using Ctrl+C, it will create the `peers.csv` and `peers_graph.csv` output files filling them with information it had at the moment when it was interrupted.

# mapbtc

## Introduction

mapbtc maps out the Bitcoin peer-to-peer network, creating a CSV file with
information about discovered nodes as well as a CSV file describing how the
peer nodes are connected to each other.

mapbtc is written in C, it uses Linux epoll(2) and non-blocking I/O to
communicate with peer nodes asynchronosly thus accelerating the mapping process
compared to going from node to node one-by-one and communicating synchronously.

## Usage

To build and run mapbtc:
1. Install build tools and development package for OpenSSL, e.g. on Fedora
   `sudo dnf install gcc make openssl-devel`.
2. Build mapbtc by typing `make` in it's directory.
3. Run mapbtc with `./mapbtc`, and it will begin mapping out the Bitcoin
   network.

When mapbtc finishes, it will have created two files, `peers.csv`, which
contains a CSV of discovered peers with some additional information about them
and also `peers_graph.csv` which contains a CSV table of connections between
the discovered peers.

You can interrupt mapbtc at any moment using Ctrl+C, it will create the
`peers.csv` and `peers_graph.csv` output files filling them with information it
had at the moment when it was interrupted.

## Output files

After mapbtc's process finishes or is interrupted, it creates two output files,
`peers.csv` and `peer_graph.csv`.

### peers.csv

The `peers.csv` file contains the following columns in order:
1. `IP` - the IPv6 or IPv4-mapped IPv6 address of the Bitcoin peer node.
2. `MainnetPortOpen` - whether or not mapbtc succeeded in connectin to the
   node, if 0 it might mean this peer node is inactive, not accepting
   connections from us, isn't active 24/7 or we don't have IPv6 connectivity.
3. `Protocol` - the protocol version advertised by node in it's `version`
   message.
4. `Services` - decimal value of the services field from the `version` message
   of the peer node.
5. `UserAgent` - the user agent string from the `version` message of
   peer node, the maximum length of this field is 127 so if the user
   agent string of the peer node is longer than that it'll get
   truncated to 127 characters.
6. `StartHeight` - the node's block height it advertised in it's
   `version` message.

### peer_graph.csv

The `peer_graph.csv` file contains a graph describing how peer nodes are
connected to each other, or more precisely, which peer nodes know which other
peer nodes. The file has two columns in order:
1. `DstNode` - the IPv6 or IPv4-mapped IPv6 address of a peer node.
2. `SrcNode` - the IPv6 or IPv4-mapped IPv6 address of the node, or the seed
   domain name, from which we got the `DstNode` address from.

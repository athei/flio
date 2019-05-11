# flio

flio is an effort to write a secure and modular fileserver using the SMB2 (and higher) protocol. Besides all kind of popritary implementations (Apple, Microsoft, ...) there is only Samba as mature open source implementation. Samba is a fine piece of software but really hard to use when you only want a file server for your embedded device:

* It is huge (> 20MB) and not modular. You pay for all enterprise stuff when alle you want is a simple file server.
* It is GPLv3 licencsed which may hinder adoption.
* It is is written in C which is less than optimal for a software that must handle adversarial input

# Goals
We align our goals so that we improve on these points by the following means.
* flio is written in safe Rust which offers much stronger security properties than C
* flio is MIT licensed for easy adoption
* Every optional component should be easily removeable (through cargo features) to reduce the minimum size

# Project Structure
The project shall consist of the following crates.
## smb2-packet
This create parses the wire representation of the protocol to semantically strong data structures. It also does the reverse: Serializing data structures to the wire representation. No other crate should ever touch wire data. This way we contain most of the critical handling of adversarial data in this crate.

## smb2-server
The server state machine that implements the smb2 protocol from a server perspective and depends on the smb2-packet crate. It implements everything but I/O. Therefore it does not impose any execution model (asynchronous vs. synchronous) on the user or does any I/O at all. These tasks are all delegated to the users of this crate (probably through traits). This allows us to easily test this crate by suppyling mock traits.

## flio
The actual server implementation that handles the I/O and execution model (probably using tokio wtith async/await).

# no_std
All crates but the actual server flio should be able to work in a no_std environment to allow for the development of alternative servers on smb2-server that work in more constraint environments.

# Current State
The only crate that exists today is smb2-packet which is approximatly half done to parse
all the required requests. After that the serializing part will be implemented which is arguably
eassier. The automated testing is done with packet traces from various implementations talking to each other.
The interface is still a little awkward because without a user it is not clear what is needed here.
This will improve once the smb2-server and flio crates are started.

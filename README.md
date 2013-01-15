# Akero [![Build Status](https://travis-ci.org/busyloop/akero.png?branch=master)](https://travis-ci.org/busyloop/akero) [![Dependency Status](https://gemnasium.com/busyloop/akero.png)](https://gemnasium.com/busyloop/akero)

Akero ([ἄγγελος](http://en.wiktionary.org/wiki/%F0%90%80%80%F0%90%80%90%F0%90%80%AB), messenger) is an easy-to-use library for peer-to-peer [public key cryptography](http://en.wikipedia.org/wiki/Public-key_cryptography). It enables two or more endpoints to exchange encrypted and/or signed messages without requiring a pre-shared secret.

Under the hood Akero uses standard OpenSSL primitives. Each instance wraps a [RSA](http://en.wikipedia.org/wiki/RSA)-keypair, a corresponding [X.509 certificate](http://en.wikipedia.org/wiki/X.509) and exchanges self-signed messages ([PKCS#7](https://tools.ietf.org/html/rfc2315)) with other instances.

Akero does not try to be a substitute for a fully featured [PKI](http://en.wikipedia.org/wiki/Public_key_infrastructure). It is meant to be used as a building block in scenarios where trust-relationships and keyrings can be externally managed, and where the complexity of traditional solutions (X.509 PKI, OpenPGP, homegrown RSA) yields no tangible benefits.

## Features

* Secure 1-to-n messaging (sign-only -or- sign->encrypt->sign)
* Low complexity; easy to use, understand and review (only 166 lines of code)
* Transport agnostic; messages and certificates are self-contained, ascii-armored (base64)
* Built on standard OpenSSL primitives, no homegrown algorithms
* [100%](https://busyloop.net/oss/akero/coverage/) test coverage


## Usage

```ruby
# Alice, Bob and Charlie are Akero instances
alice = Akero.new
bob = Akero.new
charlie = Akero.new

# Inspect Alice's keypair fingerprint
alice.id # => "AK:12:34:56:..."

# Alice signs a message
signed_msg = alice.sign("Hello world!")

# Anyone can receive this message and extract
# Alice's fingerprint and public key from it
msg = bob.receive(signed_msg)
msg.body # => "Hello world!"
msg.from # => "AK:12:34:56:..."
msg.from_pk # => "(alice-public-key)"

# Bob encrypts a message for Alice
bobs_msg = bob.encrypt(msg.from_pk, "Hello Alice!")
 
# Alice can receive it...
msg = alice.receive(bobs_msg)
msg.body # => "Hello Alice!"
msg.from # => "AK:ab:cd:ef:..."
msg.from_pk # => "(bob-public-key)"

# ...and Charlie can't
msg = charlie.receive(bobs_msg) # => Exception is raised

# Alice encrypts a message for Bob and Charlie
msg = alice.encrypt([bob.public_key, charlie.public_key], "Hello!")

# Save Alice to a file
File.open('/tmp/alice.akr', 'w') { |f| f.write(alice.private_key) }

# And load her again
new_alice = Akero.load(File.read('/tmp/alice.akr'))

```

## Documentation

* [API Docs](http://rubydoc.info/gems/akero/Akero)
* [Spec](https://github.com/busyloop/akero/blob/master/spec/akero_spec.rb)

## Benchmarks

![Throughput](http://github.com/busyloop/akero/raw/master/benchmark/bm_rate.png)
![Message size](http://github.com/busyloop/akero/raw/master/benchmark/bm_size.png)

The above charts were generated using MRI 1.9.3p362 (x86_64-linux) on an [AMD Turion II Neo N40L](http://www.cpubenchmark.net/cpu.php?cpu=AMD+Turion+II+Neo+N40L+Dual-Core) CPU.
You may run the benchmarks on your own machine with `rake benchmark`.

## License (MIT)

Copyright (c) 2012 moe@busyloop.net

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


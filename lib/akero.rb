# Copyright (c) 2012 moe@busyloop.net
# 
# MIT License
# 
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
# 
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

require "akero/version"

require 'openssl'
require 'base64'

# Akero is an easy-to-use library for peer-to-peer public key cryptography.
#
# Tested on: MRI 1.8.7, MRI 1.9.2, MRI 1.9.3, RBX 1.8, RBX 1.9
# (JRuby may be added in the future but is currently NOT supported)
class Akero
  # Akero::Message wraps a received message.
  class Message
    # @return [String] Message body
    attr_reader :body
    # @return [Symbol] Message type (:signed or :encrypted)
    attr_reader :type

    # @private
    def initialize(body, signer_cert, type)
      @body, @signer_cert, @type = body, signer_cert, type
    end

    # @private
    def inspect
      "#<Akero::Message @type=#{@type} @from=#{from} @body=(#{@body.length} bytes)>"
    end

    # @!attribute [r] from
    # @return [String] Sender Fingerprint
    def from
      Akero.fingerprint_from_cert(@signer_cert)
    end

    # @!attribute [r] from_pk
    # @return [String] Sender public key
    def from_pk
      Akero.replate(@signer_cert.to_s, PLATE_CERT)
    end
  end
end

class Akero
  ERR_MSG_MALFORMED_ENV = "Malformed message: Could not parse envelope" # @private
  ERR_MSG_MALFORMED_BODY = "Malformed message: Could not parse body; POSSIBLE SPOOF ATTEMPT" # @private
  ERR_PKEY_CORRUPT = "Invalid private key (checksum mismatch)" # @private
  ERR_CERT_CORRUPT = "Invalid certificate" # @private
  ERR_INVALID_RECIPIENT = "Invalid recipient (must be a String)" # @private
  ERR_INVALID_RECIPIENT_CERT = "Invalid recipient (corrupt public key?)" # @private
  ERR_DECRYPT = "Could not decrypt message" # @private
  ERR_MSG_NOT_STRING_NOR_PKCS7 = "Message must be of type String or OpenSSL::PKCS7" # @private
  ERR_MSG_CORRUPT_CERT = "Malformed message: Embedded certificate could not be verified; POSSIBLE SPOOF ATTEMPT!" # @private
  ERR_MSG_TOO_MANY_SIGNERS = "Corrupt message: Zero or multiple signers, expected exactly 1; POSSIBLE SPOOF ATTEMPT" # @private

  PKEY_HEADER = "-----BEGIN AKERO PRIVATE KEY-----\n" # @private
  PKEY_FOOTER = "-----END AKERO PRIVATE KEY-----\n" # @private
  PLATE_CERT = ['CERTIFICATE','AKERO PUBLIC KEY'] # @private
  PLATE_SIGNED = ['PKCS7', 'AKERO SIGNED MESSAGE'] # @private
  PLATE_CRYPTED = ['PKCS7', 'AKERO SECRET MESSAGE'] # @private

  DEFAULT_RSA_BITS = 2048

  # Unique fingerprint of this Akero keypair.
  #
  # @return [String] Akero fingerprint
  def id
    Akero.fingerprint_from_cert(@cert)
  end

  # Create a new Akero instance.
  #
  # @example Create new Akero instance with default settings
  #   Akero.new
  #
  # @example Create new Akero instance with a 4096-bit key
  #   Akero.new(4096)
  #
  # @example Create new Akero instance with a 4096-bit key and SHA512 digest
  #   Akero.new(4096, OpenSSL::Digest::SHA512)
  #
  # @param [Integer] rsa_bits RSA key length
  # @param [OpenSSL::Digest] sign_digest Signature digest
  # @return [Akero] New Akero instance
  def initialize(rsa_bits=DEFAULT_RSA_BITS, sign_digest=OpenSSL::Digest::SHA512)
    @key, @cert = generate_keypair(rsa_bits, sign_digest) unless rsa_bits.nil?
  end

  # Load an Akero identity.
  # 
  # @example Load previously stored private key
  #   Akero.load(File.read('/tmp/alice.akr'))
  #
  # @param [String] private_key Akero private key
  # @return [Akero] New Akero instance
  def self.load(private_key)
    inner = Base64.decode64(private_key[PKEY_HEADER.length..private_key.length-PKEY_FOOTER.length])
    if inner[0..63] != OpenSSL::Digest::SHA512.new(inner[64..-1]).digest
      raise RuntimeError, ERR_PKEY_CORRUPT
    end
    cert_len = inner[64..65].unpack('S')[0]
    akero = Akero.new(nil)
    akero.instance_variable_set(:@cert, OpenSSL::X509::Certificate.new(inner[66..66+cert_len]))
    akero.instance_variable_set(:@key, OpenSSL::PKey::RSA.new(inner[66+cert_len..-1]))
    akero
  end

  # Akero public key.
  #
  # Share this with other Akero instances that you
  # wish to receive encrypted messages from.
  #
  # @return [String] Public key (ascii armored)
  def public_key
    Akero::replate(@cert.to_s, Akero::PLATE_CERT)
  end

  # Private key (do not share this with anyone!)
  # 
  # @example Save and load an Akero identity
  #   alice = Akero.new
  #   # Save
  #   File.open('/tmp/alice.akr', 'w') { |f| f.write(alice.private_key) }
  #   # Load
  #   new_alice = Akero.load(File.read('/tmp/alice.akr'))
  # 
  # @return [String] Private key (ascii armored)
  # @see Akero#load
  def private_key
    # We do not use PKCS#12 ("PFX") for serialization here
    # because of http://www.cs.auckland.ac.nz/~pgut001/pubs/pfx.html
    cert_der = @cert.to_der
    out = [cert_der.length].pack('S')
    out << cert_der
    out << @key.to_der
    out.insert(0, OpenSSL::Digest::SHA512.new(out).digest)
    PKEY_HEADER+Base64.encode64(out)+PKEY_FOOTER
  end

  # Sign a message.
  #
  # @param [String] plaintext The message to sign (binary safe)
  # @return [String] Akero signed message
  def sign(plaintext)
    Akero.replate(_sign(plaintext).to_s, Akero::PLATE_SIGNED)
  end

  # Sign->encrypt->sign a message for 1 or more recipients.
  #
  # Only the listed recipients can decrypt the message-body
  # but anyone can extract the sender's public key.
  #
  # @example Alice encrypts a message to Bob
  #   alice = Akero.new
  #   bob = Akero.new
  #   ciphertext = alice.encrypt(bob.public_key, "Hello Bob!")
  #
  # @example Alice encrypts a message to Bob and Charlie
  #   alice = Akero.new
  #   bob = Akero.new
  #   charlie = Akero.new
  #   ciphertext = alice.encrypt([bob.public_key, charlie.public_key], "Hello Bob and Charlie!")
  #
  # @param [Array] to Akero public keys of recipients
  # @param [String] plaintext The message to encrypt (binary safe)
  # @return [String] Akero secret message
  def encrypt(to, plaintext)
    to = [to] unless to.is_a? Array
    to = to.map { |e| 
      case e
        when String
          begin
            OpenSSL::X509::Certificate.new(Akero.replate(e, Akero::PLATE_CERT, true))
          rescue OpenSSL::X509::CertificateError
            raise RuntimeError, ERR_INVALID_RECIPIENT_CERT
          end
        else
          raise RuntimeError, ERR_INVALID_RECIPIENT
      end
    }
    Akero.replate(_sign(_encrypt(to, _sign(plaintext, false))).to_s, PLATE_CRYPTED)
  end

  # Receive an Akero message.
  #
  # @param [String] ciphertext Akero Message
  # @return [Akero::Message] Message_body, signer_certificate, body_type
  def receive(ciphertext)
    ciphertext = Akero.replate(ciphertext, Akero::PLATE_CRYPTED, true)
    begin
      body, signer_cert, body_type = verify(ciphertext, nil)
    rescue ArgumentError
      raise RuntimeError, ERR_MSG_MALFORMED_ENV
    end

    case body_type.ord
      when 0x00
        # public message (signed)
        return Message.new(body, signer_cert, :signed)
      when 0x01
        # private message (signed, crypted, signed)
        signed_plaintext = _decrypt(body)
        plaintext, verified_cert, body_type = verify(signed_plaintext, signer_cert)
        msg = Message.new(plaintext, signer_cert, :encrypted)
        return msg
    end
    raise RuntimeError, ERR_MSG_MALFORMED_BODY
  end

  # @private
  def inspect
    "#<Akero id=#{id}>"
  end

  # @private
  def to_s
    inspect
  end
 
  #---------------------------------------------------------------------------
  protected

  # Swap the "license plates" on an ascii-armored message.
  # This is done for user-friendliness, so stored Akero
  # messages and keys can be easily identified at a glance.
  #
  # @param [String] msg Message to be replated
  # @param [Array] plates Array of the two plates to swap
  # @param [Boolean] reverse Reverse the swap?
  # @return [String] The replated message
  def self.replate(msg, plates, reverse=false)
    a,b = reverse ? [1,0] : [0,1]
    "-----BEGIN #{plates[b]}-----#{msg.strip[plates[a].length+16..-(plates[a].length+15)]}-----END #{plates[b]}-----\n"
  end

  # Extract fingerprint from an Akero public key.
  #
  # @return [String] Akero fingerprint
  def self.fingerprint_from_cert(cert)
    cert.extensions.map.each do |e|
      return "AK:#{e.value}" if e.oid == 'subjectKeyIdentifier'
    end
    raise RuntimeError, ERR_CERT_CORRUPT
  end
 
  #---------------------------------------------------------------------------
  private 

  def _decrypt(crypted_msg)
    begin
      OpenSSL::PKCS7.new(crypted_msg).decrypt(@key, @cert)
    rescue OpenSSL::PKCS7::PKCS7Error, "decrypt error"
      raise RuntimeError, ERR_DECRYPT
    end
  end

  def _encrypt(to, msg, cipher=nil)
    cipher ||= OpenSSL::Cipher::new("AES-256-CFB")
    OpenSSL::PKCS7::encrypt(to, msg.to_der, cipher, OpenSSL::PKCS7::BINARY)
  end

  def _sign(message, embed_cert=true)
    flags = embed_cert ? OpenSSL::PKCS7::BINARY : (OpenSSL::PKCS7::BINARY | OpenSSL::PKCS7::NOCERTS)
    case message
      when String
        type = 0x00
      when OpenSSL::PKCS7
        type = 0x01
      else
        raise RuntimeError, ERR_MSG_NOT_STRING_NOR_PKCS7
    end
    message = message.to_der if message.is_a? OpenSSL::PKCS7
    OpenSSL::PKCS7::sign(@cert, @key, type.chr + message, [], flags)
  end

  def verify(signed_msg, cert)
    signed_msg = OpenSSL::PKCS7.new(signed_msg) if signed_msg.is_a? String
    store = OpenSSL::X509::Store.new

    if cert.nil?
      if signed_msg.certificates.nil? or signed_msg.certificates.length != 1
        raise RuntimeError, ERR_MSG_TOO_MANY_SIGNERS
      end

      cert = signed_msg.certificates[0]
    end

    unless signed_msg.verify([cert], store, nil, OpenSSL::PKCS7::NOINTERN | OpenSSL::PKCS7::NOVERIFY)
      raise RuntimeError, ERR_MSG_CORRUPT_CERT
    end

    [signed_msg.data[1..-1], cert, signed_msg.data[0]]
  end

  # Generate new RSA keypair and certificate.
  #
  # @param [Integer] rsa_bits RSA key length
  # @param [OpenSSL::Digest] sign_digest Signature digest
  # @return [Array] rsa_keypair, certificate
  def generate_keypair(rsa_bits=DEFAULT_RSA_BITS, sign_digest=OpenSSL::Digest::SHA512)
    cn = "Akero #{Akero::VERSION}"
    rsa = OpenSSL::PKey::RSA.new(rsa_bits)

    cert = OpenSSL::X509::Certificate.new
    cert.version = 3
    cert.serial = rand(2**42)
    name = OpenSSL::X509::Name.parse("/CN=#{cn}")
    cert.subject = name
    cert.issuer = name
    cert.not_before = Time.now
    # valid until 2038-01-19 04:14:06 +0100
    cert.not_after = Time.at(2147483646)
    cert.public_key = rsa.public_key
    
    ef = OpenSSL::X509::ExtensionFactory.new(nil, cert)
    ef.issuer_certificate = cert
    cert.extensions = [
      ef.create_extension("basicConstraints","CA:FALSE"),
      ef.create_extension("subjectKeyIdentifier", "hash"),
    ]
    aki = ef.create_extension("authorityKeyIdentifier",
                              "keyid:always,issuer:always")
    cert.add_extension(aki)
    cert.sign(rsa, sign_digest.new)
    [rsa, cert]
  end
end


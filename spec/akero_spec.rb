# frozen_string_literal: true
require 'spec_helper'
require 'openssl'

describe Akero do
  subject { Akero.new(1024) }
  describe '#new' do
    it 'returns instance with unique fingerprint' do
      memo = {}
      10.times do
        id = Akero.new.id
        memo.should_not include id
        memo[id] = true
      end
    end
  end

  describe '#id' do
    it 'returns a String that looks like an Akero fingerprint' do
      subject.id.should be_a String
      subject.id.should match /^AK(:([a-fA-Z0-9]){2}){20}$/
    end
  end

  describe '#private_key' do
    describe 'return value' do
      it 'is a String that looks like an Akero private key' do
        subject.private_key.should be_a String
        subject.private_key.should match /^#{Akero::PKEY_HEADER}/
        subject.private_key.should match /\n#{Akero::PKEY_FOOTER}$/
      end

      it 'can be loaded by Akero' do
        bob = Akero.load(subject.private_key)
        bob.id.should == subject.id
        bob.public_key.should == subject.public_key
      end
    end
  end

  describe '#public_key' do
    describe 'return value' do
      it 'is a String that looks like an Akero public key' do
        subject.public_key.should be_a String
        subject.public_key.should match /^-----BEGIN #{Akero::PLATE_CERT[1]}-----\n/
        subject.public_key.should match /\n-----END #{Akero::PLATE_CERT[1]}-----\n$/
      end

      it 'raises RuntimeError when trying to load as private key' do
        lambda do
          bob = Akero.load(subject.public_key)
          bob.id.should == subject.id
          bob.public_key.should == subject.public_key
        end.should raise_error RuntimeError, Akero::ERR_PKEY_CORRUPT
      end
    end
  end

  describe '#sign' do
    [true, false].each do |ascii_armor|
      describe "ascii_armor=#{ascii_armor}" do
        describe 'return value' do
          if ascii_armor
            it 'is a String that looks like an Akero signed message' do
              plaintext = 'Hello world!'
              signed_msg = subject.sign(plaintext, ascii_armor)
              signed_msg.should be_a String
              signed_msg.should match /^-----BEGIN #{Akero::PLATE_SIGNED[1]}-----\n/
              signed_msg.should match /\n-----END #{Akero::PLATE_SIGNED[1]}-----\n$/
            end
          end

          it 'contains valid signature' do
            plaintext = 'Hello world!'
            signed_msg = subject.sign(plaintext, ascii_armor)
            bob = Akero.new
            msg = bob.receive(signed_msg)
            msg.from.should == subject.id
            msg.from_pk.should == subject.public_key
            msg.body.should == plaintext
            msg.type.should == :signed
          end
        end
      end
    end
  end

  describe '#encrypt' do
    [true, false].each do |ascii_armor|
      describe "ascii_armor=#{ascii_armor}" do
        describe 'return value' do
          if ascii_armor
            it 'is a String that looks like an Akero secret message' do
              plaintext = 'Hello world!'
              ciphertext = subject.encrypt(subject.public_key, plaintext, ascii_armor)
              ciphertext.should be_a String
              ciphertext.should match /^-----BEGIN #{Akero::PLATE_CRYPTED[1]}-----\n/
              ciphertext.should match /\n-----END #{Akero::PLATE_CRYPTED[1]}-----\n$/
            end
          end

          it 'raises RuntimeError on invalid recipient (invalid public key)' do
            lambda do
              msg = 'Hello world!'
              ciphertext = subject.encrypt([subject.public_key, 'foo'], msg)
            end.should raise_error RuntimeError, Akero::ERR_INVALID_RECIPIENT_CERT
          end

          it 'raises RuntimeError on invalid recipient (wrong type)' do
            lambda do
              msg = 'Hello world!'
              ciphertext = subject.encrypt([subject.public_key, 42], msg)
            end.should raise_error RuntimeError, Akero::ERR_INVALID_RECIPIENT
          end

          it 'raises RuntimeError when message is not String' do
            lambda do
              msg = 'Hello world!'
              ciphertext = subject.encrypt(subject.public_key, 42)
            end.should raise_error RuntimeError, Akero::ERR_MSG_NOT_STRING_NOR_PKCS7
          end
        end
      end
    end
  end

  describe '#receive' do
    [true, false].each do |ascii_armor|
      describe "ascii_armor=#{ascii_armor}" do
        it 'decrypts message that was encrypted for self' do
          plaintext = 'Hello world!'
          ciphertext = subject.encrypt(subject.public_key, plaintext, ascii_armor)
          msg = subject.receive(ciphertext)
          msg.body.should == plaintext
          msg.type.should == :encrypted
        end

        it 'decrypts message that was encrypted for self and other recipients' do
          plaintext = 'Hello world!'
          alice = Akero.new
          bob   = Akero.new
          ciphertext = subject.encrypt([alice.public_key, subject.public_key, bob.public_key], plaintext, ascii_armor)
          msg = subject.receive(ciphertext)
          msg.body.should == plaintext
          msg.type.should == :encrypted
        end

        it 'fails to decrypt message that was encrypted only for other recipients' do
          lambda do
            plaintext = 'Hello world!'
            alice = Akero.new
            bob   = Akero.new
            ciphertext = subject.encrypt([alice.public_key, bob.public_key], plaintext, ascii_armor)
            msg = subject.receive(ciphertext)
            msg.body.should == plaintext
            msg.type.should == :encrypted
          end.should raise_error RuntimeError, Akero::ERR_DECRYPT
        end

        it 'extracts signature from signed message' do
          plaintext = 'Hello world!'
          alice = Akero.new
          signed_msg = subject.sign(plaintext, ascii_armor)
          msg = alice.receive(signed_msg)
          msg.body.should == plaintext
          msg.type.should == :signed
        end

        it 'raises RuntimeError on invalid message' do
          lambda do
            subject.receive('foobar')
          end.should raise_error RuntimeError # , Akero::ERR_MSG_MALFORMED_ENV
        end

        it 'raises RuntimeError when payload does not match envelope signature' do
          lambda do
            oscar = Akero.new
            raw_key = subject.send(:instance_variable_get, '@cert')
            a = subject.send(:_encrypt, [raw_key], subject.send(:_sign, 'foobar'))
            b = oscar.send(:_sign, a)
            c = ascii_armor ? Akero.replate(b.to_s, Akero::PLATE_CRYPTED) : b.to_der
            subject.receive(c)
          end.should raise_error RuntimeError, Akero::ERR_MSG_CORRUPT_CERT
        end

        it 'raises RuntimeError on malformed inner message' do
          lambda do
            key, cert = subject.send(:generate_keypair, 1024)
            env = OpenSSL::PKCS7.sign(cert, key, 0xff.chr, [], OpenSSL::PKCS7::BINARY)
            broken_msg = Akero.replate(env.to_s, Akero::PLATE_CRYPTED)
            subject.receive(broken_msg)
          end.should raise_error RuntimeError, Akero::ERR_MSG_MALFORMED_BODY
        end

        it 'raises RuntimeError on unsigned message' do
          lambda do
            raw_key = subject.send(:instance_variable_get, '@cert')
            env = OpenSSL::PKCS7.encrypt([raw_key], 'foobar', OpenSSL::Cipher.new('AES-256-CFB'), OpenSSL::PKCS7::BINARY)
            broken_msg = Akero.replate(env.to_s, Akero::PLATE_CRYPTED)
            subject.receive(broken_msg)
          end.should raise_error RuntimeError, Akero::ERR_MSG_TOO_MANY_SIGNERS
        end
      end
    end
  end

  describe '#verify' do
    it 'raises RuntimeError when embedded certificate can not be verified' do
      lambda do
        fake_msg = mock('fake_msg')
        fake_msg.stub(:verify).and_return(false)
        fake_msg.stub_chain(:certificates, :length).and_return(1)
        fake_msg.stub_chain(:certificates, :[]).and_return(nil)
        subject.send(:verify, fake_msg, nil)
      end.should raise_error RuntimeError, Akero::ERR_MSG_CORRUPT_CERT
    end
  end

  describe '#inspect' do
    it 'returns a summary String' do
      s = subject.inspect
      s.should match /id=AK:/
    end
  end

  describe '#to_s' do
    it 'returns the same value as #inspect' do
      subject.to_s.should == subject.inspect
    end
  end

  describe '.fingerprint_from_cert' do
    it 'raises RuntimeError on invalid cert' do
      mock_cert = mock('mock_cert')
      mock_cert.stub_chain(:extensions, :map, :each).and_return(nil)
      lambda do
        Akero.fingerprint_from_cert(mock_cert)
      end.should raise_error RuntimeError, Akero::ERR_CERT_CORRUPT
    end
  end

  describe Akero::Message do
    describe '#inspect' do
      it 'returns a summary String' do
        signed_msg = subject.sign('')
        msg = subject.receive(signed_msg)
        s = msg.inspect
        s.should be_a String
        s.should match /@type=/
        s.should match /@from=/
        s.should match /@body=/
      end
    end
  end
end

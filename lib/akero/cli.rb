# frozen_string_literal: true
require 'akero/version'
require 'akero'
require 'optix'

class Akero
  class Cli < Optix::Cli
    Optix.command do
      text "Akero v#{Akero::VERSION}"
      opt :private_key, 'Path to private key', short: :i, default: File.join(ENV['HOME'], '.akero_id')
      opt :version, 'Print version and exit', short: :none
      trigger :version do
        puts "Akero v#{Akero::VERSION}"
      end
      filter do |_cmd, opts, _argv|
        if ENV['AKERO_PK']&.starts_with? Akero::PKEY_HEADER
          Akero.load(ENV['AKERO_PK'])
        elsif File.exists? opts[:private_key]
          opts[:akero_instance] = Akero.load(File.read(opts[:private_key]))
        else
          puts "Private key not found. Generating a new #{Akero::DEFAULT_RSA_BITS} bits RSA key and saving to #{opts[:private_key]} ..."
          opts[:akero_instance] = Akero.new
          File.write(opts[:private_key], opts[:akero_instance].private_key)
        end

        $quiet = opts[:quiet]
        $quiet = true unless STDOUT.isatty
      end
    end

    desc "Print public key to stdout"
    text "Print public key to stdout."
    def pk(cmd, opts, argv)
      puts opts[:akero_instance].public_key
    end

    desc "Print id (fingerprint) to stdout"
    text "Print id (fingerprint) to stdout."
    def id(cmd, opts, argv)
      puts opts[:akero_instance].id
    end

    desc "Read plain from stdin, print encrypted message to stdout"
    text "Read plain from stdin, print encrypted message to stdout."
    text ''
    text "The path to at least one file containing a recipient"
    text "public key must be given as a parameter."
    opt :armor, "Output in ASCII armored format", short: :none, default: true
    params "<path to recipient public_key> [..]"
    def encrypt(cmd, opts, argv)
      raise Optix::HelpNeeded if argv.length == 0
      recipients = []
      argv.each do |path|
        recipients << File.read(path)
      end
      puts opts[:akero_instance].encrypt(recipients, STDIN.read, opts[:armor])
    end

    desc "Read plain from stdin, print signed message to stdout"
    text "Read plain from stdin, print signed message to stdout."
    opt :armor, "Output in ASCII armored format", short: :none, default: true
    def sign(cmd, opts, argv)
      puts opts[:akero_instance].sign(STDIN.read, opts[:armor])
    end

    desc "Read signed/encrypted message from stdin, print plain to stdout"
    text "Read signed or encrypted message from stdin, print plain to stdout."
    opt :key, "Write sender key to stderr", default: false
    def receive(cmd, opts, argv)
      msg = opts[:akero_instance].receive(STDIN.read)
      puts msg.body
      STDERR.puts msg.from_pk if opts[:key]
    end
  end
end

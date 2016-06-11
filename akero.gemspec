# -*- encoding: utf-8 -*-
# frozen_string_literal: true
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'akero/version'

Gem::Specification.new do |gem|
  gem.name          = 'akero'
  gem.version       = Akero::VERSION
  gem.authors       = ['Moe']
  gem.email         = ['moe@busyloop.net']
  gem.description   = 'Easy peer-to-peer public key cryptography'
  gem.summary       = 'Easy peer-to-peer public key cryptography'
  gem.homepage      = 'https://github.com/busyloop/akero'

  gem.files         = `git ls-files`.split($INPUT_RECORD_SEPARATOR)
  gem.executables   = gem.files.grep(%r{^bin/}).map { |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ['lib']

  gem.required_ruby_version = '>= 2.3.1'

  gem.add_dependency 'optix'

  gem.add_development_dependency 'rb-inotify'
  gem.add_development_dependency 'guard'
  gem.add_development_dependency 'guard-rspec'
  gem.add_development_dependency 'rake'
  gem.add_development_dependency 'simplecov'
  gem.add_development_dependency 'rspec', '= 2.12.0'
  gem.add_development_dependency 'b'
  gem.add_development_dependency 'gnuplot'
  gem.add_development_dependency 'yard'
  gem.add_development_dependency 'bump'
end

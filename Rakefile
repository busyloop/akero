require "bundler/gem_tasks"

require 'rspec/core/rake_task'

task :default => :test

RSpec::Core::RakeTask.new("test:spec") do |t|
    t.pattern = 'spec/**/*_spec.rb'
    t.rspec_opts = '--fail-fast -b -c -f documentation --tag ~benchmark'
end

desc 'Run test suite'
task :test => [ 'test:spec' ]

desc "Run benchmark suite"
task :benchmark do
  require 'akero/benchmark'
  Akero::Benchmark.run!
end

namespace :docs do
  task :push do
    `bl_www_sync akero coverage`
  end
end

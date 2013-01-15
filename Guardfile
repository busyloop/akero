my_code = <<'RUBY_CODE'
  if type == 'failed'
    system "ssh 192.168.1.106 '~/bin/keyboard_leds -c1 >/dev/null'"
    system "ssh 192.168.1.106 'afplay ~/.fail.wav'"
  end
  if type == 'success'
    system "ssh 192.168.1.106 '~/bin/keyboard_leds -c0 >/dev/null'"
    system "ssh 192.168.1.106 'afplay ~/.success.wav'"
  end
RUBY_CODE

notification :eval_notifier, :code => my_code

guard 'rspec', :cli => '--color --format doc' do
  watch(%r{^spec/.+_spec\.rb$})
  watch(%r{^lib/(.+)\.rb$})     { |m| "spec/lib/#{m[1]}_spec.rb" }
  watch('spec/spec_helper.rb')  { "spec" }
end

require 'bundler/setup'
require 'rspec'

RSpec.configure do |config|
  config.before do
    OmniAuth.config.test_mode = true
  end

  config.after do
    OmniAuth.config.test_mode = false
  end
end

require 'spec_helper'
require 'omniauth-soundcloud'

describe OmniAuth::Strategies::SoundCloud do
  let(:request) do
    double('request',
            :params => {},
            :cookies => {},
            :env => {})
  end

  subject do
    OmniAuth::Strategies::SoundCloud.new(nil, @options || {}).tap do |strategy|
      allow(strategy).to receive(:request).and_return(request)
    end
  end

  before do
    OmniAuth.config.test_mode = true
  end

  after do
    OmniAuth.config.test_mode = false
  end

  describe '#client' do
    it 'has the correct SoundCloud site' do
      expect(subject.client.site).to eq("https://secure.soundcloud.com")
    end

    it 'has the correct authorization url' do
      expect(subject.client.options[:authorize_url]).to eq("/authorize")
    end

    it 'has the correct token url' do
      expect(subject.client.options[:token_url]).to eq('/oauth/token')
    end
  end

  describe '#callback_path' do
    it 'has the correct callback path' do
      expect(subject.callback_path).to eq('/auth/soundcloud/callback')
    end
  end

  describe '#authorize_params' do
    it 'includes display parameter from request when present' do
      allow(request).to receive(:params).and_return({ 'display' => 'touch' })
      
      expect(subject.authorize_params).to be_a(Hash)
      expect(subject.authorize_params[:display]).to eq('touch')
    end

    it 'includes state parameter from request when present' do
      allow(request).to receive(:params).and_return({ 'state' => 'some_state' })

      expect(subject.authorize_params).to be_a(Hash)
      expect(subject.authorize_params[:state]).to eq('some_state')
    end

    it 'overrides default scope with parameter passed from request' do
      allow(request).to receive(:params).and_return({ 'scope' => 'email' })

      expect(subject.authorize_params).to be_a(Hash)
      expect(subject.authorize_params[:scope]).to eq('email')
    end

    it "includes PKCE parameters if enabled" do
      @options = { pkce: true }

      expect(subject.authorize_params[:code_challenge]).to be_a(String)
      expect(subject.authorize_params[:code_challenge_method]).to eq("S256")
      expect(subject.session["omniauth.pkce.verifier"]).to be_a(String)
    end
  end
end

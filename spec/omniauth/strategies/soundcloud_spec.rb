require 'spec_helper'
require 'omniauth-soundcloud'

describe OmniAuth::Strategies::SoundCloud do
  let(:request) do
    double('request', params: {}, cookies: {}, env: {})
  end

  subject do
    OmniAuth::Strategies::SoundCloud.new(nil, @options || {}).tap do |strategy|
      strategy.stub(request: request)
    end
  end

  describe '#client' do
    it 'has correct Soundcloud site' do
      subject.client.site.should eq('https://api.soundcloud.com')
    end

    it 'has correct authorization url' do
      subject.client.options[:authorize_url].should eq('https://secure.soundcloud.com/authorize')
    end

    it 'has correct token url' do
      subject.client.options[:token_url].should eq('https://secure.soundcloud.com/oauth/token')
    end
  end

  describe '#callback_path' do
    it 'has correct callback path' do
      subject.callback_path.should eq('/auth/soundcloud/callback')
    end
  end

  describe '#authorize_params' do
    it 'includes display parameter from request when present' do
      request.stub(:params) { { 'display' => 'touch' } }
      subject.authorize_params.should be_a(Hash)
      subject.authorize_params[:display].should eq('touch')
    end

    it 'includes state parameter from request when present' do
      request.stub(:params) { { 'state' => 'some_state' } }
      subject.authorize_params.should be_a(Hash)
      subject.authorize_params[:state].should eq('some_state')
    end

    it 'overrides default scope with parameter passed from request' do
      request.stub(:params) { { 'scope' => 'email' } }
      subject.authorize_params.should be_a(Hash)
      subject.authorize_params[:scope].should eq('email')
    end

    it 'includes top-level options that are marked as :authorize_options' do
      @options = { authorize_options: %i[scope foo state], scope: 'bar', foo: 'baz' }

      subject.authorize_params[:scope].should eq('bar')
      subject.authorize_params[:foo].should eq('baz')
      subject.authorize_params[:state].should_not be_empty
    end

    it 'includes custom state in the authorize params' do
      @options = { state: 'qux' }

      subject.authorize_params.keys.include?('state').should be_true
      subject.session['omniauth.state'].should eq('qux')
    end

    it 'includes PKCE parameters' do
      subject.authorize_params[:code_challenge].should be_a(String)
      subject.authorize_params[:code_challenge_method].should eq('S256')
      subject.session['omniauth.pkce.verifier'].should be_a(String)
    end
  end

  describe '#token_params' do
    it 'includes any token params passed in the :token_params option' do
      @options = { token_params: { foo: 'bar', baz: 'zip' } }
      subject.authorize_params # setup session
      subject.token_params.should include('foo' => 'bar', 'baz' => 'zip')
    end

    it 'includes top-level options that are marked as :token_options' do
      @options = { token_options: %i[scope foo], scope: 'bar', foo: 'baz' }
      subject.authorize_params # setup session
      subject.token_params.should include('scope' => 'bar', 'foo' => 'baz')
    end

    it 'includes the PKCE code_verifier' do
      subject.authorize_params # setup session
      subject.token_params[:code_verifier].should be_a(String)
    end
  end
end

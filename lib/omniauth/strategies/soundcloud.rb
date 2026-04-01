# frozen_string_literal: true

require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    # Authentication strategy for connecting with Soundcloud API constructed
    # using the [OAuth 2.1 Specification](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/).
    class SoundCloud < OmniAuth::Strategies::OAuth2
      DEFAULT_SCOPE = 'non-expiring'

      option :authorize_options, %i[scope state]

      option :name, 'soundcloud'

      option :client_options,
             site: 'https://api.soundcloud.com',
             authorize_url: 'https://secure.soundcloud.com/authorize',
             token_url: 'https://secure.soundcloud.com/oauth/token',
             connection_build: proc { |builder| builder.adapter :typhoeus }

      option :access_token_options,
             header_format: 'OAuth %s',
             param_name: 'access_token'

      uid { raw_info['id'] }

      info do
        prune!(
          'nickname' => raw_info['username'],
          'name' => raw_info['full_name'],
          'image' => raw_info['avatar_url'],
          'description' => raw_info['description'],
          'urls' => {
            'Website' => raw_info['website']
          },
          'location' => raw_info['city']
        )
      end

      credentials do
        prune!(
          'expires' => access_token.expires?,
          'expires_at' => access_token.expires_at
        )
      end

      extra do
        prune!('raw_info' => raw_info)
      end

      def raw_info
        @raw_info ||= access_token.get('/me').parsed
      end

      def access_token_options
        options.access_token_options.deep_symbolize_keys
      end

      def authorize_params
        super.tap do |params|
          %w[display state scope].each do |v|
            params[v.to_sym] = request.params[v] if request.params[v]
          end

          params[:scope] ||= DEFAULT_SCOPE
          params.merge!(pkce_authorize_params)

          session['omniauth.pkce.verifier'] = options.pkce_verifier
          session['omniauth.state'] = params[:state]
        end
      end

      def token_params
        options.token_params
               .merge(options_for('token'))
               .merge(pkce_token_params)
      end

      private

      def prune!(hash)
        hash.delete_if do |_, value|
          prune!(value) if value.is_a?(Hash)
          value.nil? || (value.respond_to?(:empty?) && value.empty?)
        end
      end

      protected

      def build_access_token
        super.tap do |token|
          token.options.merge!(access_token_options)
        end
      end

      def pkce_authorize_params
        options.pkce_verifier = SecureRandom.hex(64)

        # NOTE: see https://tools.ietf.org/html/rfc7636#appendix-A
        {
          code_challenge: Base64.urlsafe_encode64(
            Digest::SHA2.digest(options.pkce_verifier),
            padding: false
          ),
          code_challenge_method: 'S256'
        }
      end

      def pkce_token_params
        { code_verifier: session.delete('omniauth.pkce.verifier') }
      end
    end
  end
end

OmniAuth.config.add_camelization 'soundcloud', 'SoundCloud'

require 'net/http'
require 'base64'
require 'rbnacl'

module Auth
  class TokenRequest
    def initialize(auth_server_url: ENV['AUTH_SERVER_URL'], email: nil, password: nil)
      @raw_url = auth_server_url
      @email = email # split on || or something to get U/N and token.
      @password = password
    end

    def auth_server_public_key
      @auth_server_public_key ||= TimeCache.new { Crypto::PublicKey.new(raw_auth_server_public_key, :base64) }
    end

    def token
      response = post_to_login!
      decrypt_response(response)
    rescue
      nil #TODO: better granularity
    end

    def key_pair
      @key_pair ||= KeyPair.new(raw_public_key: ENV['API_PUBLIC_KEY'], raw_private_key: ENV['API_PRIVATE_KEY'])
    end

    private

    def url
      @url ||= URI(@raw_url)
    end

    def raw_auth_server_public_key
      Net::HTTP.get(URI.join(url, 'public_key'))
    end

    #returns parsed, encrypted response
    def post_to_login!
      response = SignInRequest.new(URI.join(url, '/users/', 'sign_in'))
      .set_data(post_data)
      .execute!

      JSON.parse Base64.decode64 response
    end

    def decrypt_response(response)
      JSON.parse key_pair.decrypt(
        message: response['message'],
        nonce: response['nonce'],
        sender_key: auth_server_public_key.value
      )
    end

    private

    def post_data
      {
        'user[email]' => email,
        'user[password]' => password,
        'user[client]' => ENV['AUTH_CLIENT_NAME']
      }
    end

    attr_reader :email, :password
  end

  class SignInRequest
    def initialize(url)
      @url = url
    end
    attr_reader :url

    def request
      @req ||= Net::HTTP::Post.new(url)
    end

    def set_data(hash)
      request.set_form_data(hash)
      self
    end

    def execute!
      res = Net::HTTP.start(url.hostname, url.port, use_ssl: url.scheme == 'https' ) do |http|
        http.request(request)
      end

      raise "Sign In Request Failed" unless res.is_a?(Net::HTTPRedirection)

      Net::HTTP.get(URI(res['location']))
    end
  end

  class TimeCache
    def initialize(time_to_live: 5.minutes, &getter)
      @ttl = time_to_live
      @getter = getter

      update_time_to_die!
    end

    def value
      return @value unless Time.now < time_to_die || @value.nil?
      update_value!
      update_time_to_die!

      @value
    end

    private
    attr_reader :time_to_die, :ttl, :getter

    def update_value!
      @value = getter.call
    end

    def update_time_to_die!
      @time_to_die = ttl.seconds.from_now
    end
  end
end




  module Auth
    class KeyPair
      def initialize(raw_private_key: nil, raw_public_key: nil)
        @raw_private_key = raw_private_key
        @raw_public_key = raw_public_key
      end

      def public_key
        @public_key ||= Crypto::PublicKey.new(raw_public_key, :base64)
      end

      def private_key
        @private_key ||= Crypto::PrivateKey.new(raw_private_key, :base64)
      end

      def decrypt(message: '', sender_key: nil, nonce: nil)
        raise "Must provide a sender_key" if sender_key.nil?
        raise "Must provide a nonce" if nonce.nil?

        box_for(sender_key).open(Base64.decode64(nonce), Base64.decode64(message))
      end

      def encrypt(message: '', recipient_key: nil)
        raise "Must provide a recipient_key" if recipient_key.nil?

        nonce = generate_nonce!

        { nonce: Base64.encode64(nonce),
          message: Base64.encode64(box_for(recipient_key).box(nonce, message)) }
      end

      private

      attr_reader :raw_private_key, :raw_public_key

      # A nonce is a non-secret, random string. No nonce should never be used more
      # than once with a given public key, or else you're exposed to nasty attacks.
      # This generates a random 24-byte nonce.
      def generate_nonce!
        Crypto::Random.random_bytes(24)
      end

      def box_for(pubkey)
        Crypto::Box.new(pubkey, private_key)
      end
    end
  end

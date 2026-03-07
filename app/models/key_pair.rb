class KeyPair < ApplicationRecord
  belongs_to :owner, polymorphic: true

  validates :public_key, presence: true
  validates :private_key_encrypted, presence: true

  def self.generate_for(owner)
    private_key = RbNaCl::PrivateKey.generate
    public_key = private_key.public_key

    create!(
      owner: owner,
      public_key: Base64.strict_encode64(public_key.to_bytes),
      private_key_encrypted: encrypt_private_key(private_key.to_bytes)
    )
  end

  def private_key_bytes
    decrypt_private_key(private_key_encrypted)
  end

  def public_key_bytes
    Base64.strict_decode64(public_key)
  end

  private

  def self.encrypt_private_key(key_bytes)
    # Encrypt the private key using the Rails secret key base
    encryptor = ActiveSupport::MessageEncryptor.new(
      ActiveSupport::KeyGenerator.new(Rails.application.secret_key_base).generate_key("key_pair_encryption", 32)
    )
    encryptor.encrypt_and_sign(Base64.strict_encode64(key_bytes))
  end

  def decrypt_private_key(encrypted)
    encryptor = ActiveSupport::MessageEncryptor.new(
      ActiveSupport::KeyGenerator.new(Rails.application.secret_key_base).generate_key("key_pair_encryption", 32)
    )
    Base64.strict_decode64(encryptor.decrypt_and_verify(encrypted))
  end
end

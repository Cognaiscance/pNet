class ClearBcryptApiKeyDigests < ActiveRecord::Migration[8.1]
  def up
    App.update_all(api_key_digest: nil)
  end
end

class AddPeerPublicKeyToConnections < ActiveRecord::Migration[8.1]
  def change
    add_column :connections, :peer_public_key, :text
  end
end

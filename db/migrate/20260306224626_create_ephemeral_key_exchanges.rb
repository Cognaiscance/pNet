class CreateEphemeralKeyExchanges < ActiveRecord::Migration[8.1]
  def change
    create_table :ephemeral_key_exchanges do |t|
      t.references :connection, null: false, foreign_key: true
      t.text :peer_public_key
      t.datetime :timeout
      t.timestamps
    end
  end
end

class CreateKeyPairs < ActiveRecord::Migration[8.1]
  def change
    create_table :key_pairs do |t|
      t.text :public_key, null: false
      t.text :private_key_encrypted, null: false
      t.string :owner_type, null: false
      t.bigint :owner_id, null: false
      t.timestamps
    end
    add_index :key_pairs, [ :owner_type, :owner_id ]
  end
end

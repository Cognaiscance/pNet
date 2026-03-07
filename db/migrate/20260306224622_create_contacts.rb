class CreateContacts < ActiveRecord::Migration[8.1]
  def change
    create_table :contacts do |t|
      t.bigint :owner_id, null: false
      t.bigint :contact_id, null: false
      t.timestamps
    end
    add_index :contacts, :owner_id
    add_index :contacts, :contact_id
    add_index :contacts, [ :owner_id, :contact_id ], unique: true
    add_foreign_key :contacts, :users, column: :owner_id
    add_foreign_key :contacts, :users, column: :contact_id
  end
end

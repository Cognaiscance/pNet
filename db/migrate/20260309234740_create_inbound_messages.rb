class CreateInboundMessages < ActiveRecord::Migration[8.1]
  def change
    create_table :inbound_messages do |t|
      t.integer :app_id, null: false
      t.string :from_user_uuid, null: false
      t.string :from_device_uuid, null: false
      t.text :payload, null: false
      t.datetime :read_at

      t.timestamps
    end

    add_index :inbound_messages, :app_id
    add_index :inbound_messages, :read_at
  end
end

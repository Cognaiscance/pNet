class CreateOutboundMessages < ActiveRecord::Migration[8.1]
  def change
    create_table :outbound_messages do |t|
      t.string :message_id
      t.text :packet_json
      t.string :host
      t.integer :port
      t.datetime :sent_at
      t.datetime :acked_at
      t.integer :retry_count, null: false, default: 0
      t.datetime :next_retry_at

      t.timestamps
    end
    add_index :outbound_messages, :message_id, unique: true
  end
end

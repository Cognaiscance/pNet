class CreateConnections < ActiveRecord::Migration[8.1]
  def change
    create_table :connections do |t|
      t.string :host_name, null: false
      t.datetime :timeout
      t.string :protocol, default: "udp"
      t.string :connectable_type, null: false
      t.bigint :connectable_id, null: false
      t.timestamps
    end
    add_index :connections, [ :connectable_type, :connectable_id ]
  end
end

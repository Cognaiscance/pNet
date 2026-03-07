class CreateApps < ActiveRecord::Migration[8.1]
  def change
    create_table :apps do |t|
      t.string :app_uuid, null: false
      t.string :app_name, null: false
      t.integer :status, default: 0, null: false
      t.string :api_key_digest
      t.string :app_api_key
      t.references :device, null: false, foreign_key: true
      t.timestamps
    end
    add_index :apps, :app_uuid, unique: true
  end
end

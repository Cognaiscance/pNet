class CreateDevices < ActiveRecord::Migration[8.1]
  def change
    create_table :devices do |t|
      t.string :uuid, null: false
      t.string :alias, null: false
      t.references :user, null: false, foreign_key: true
      t.timestamps
    end
    add_index :devices, :uuid, unique: true
  end
end

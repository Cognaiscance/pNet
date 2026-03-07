class CreateUsers < ActiveRecord::Migration[8.1]
  def change
    create_table :users do |t|
      t.string :uuid, null: false
      t.string :alias, null: false
      t.timestamps
    end
    add_index :users, :uuid, unique: true
  end
end

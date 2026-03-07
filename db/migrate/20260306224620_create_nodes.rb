class CreateNodes < ActiveRecord::Migration[8.1]
  def change
    create_table :nodes do |t|
      t.references :user, null: true, foreign_key: true
      t.references :device, null: true, foreign_key: true
      t.timestamps
    end
  end
end

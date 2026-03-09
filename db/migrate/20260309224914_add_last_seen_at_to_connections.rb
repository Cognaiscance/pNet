class AddLastSeenAtToConnections < ActiveRecord::Migration[8.1]
  def change
    add_column :connections, :last_seen_at, :datetime
  end
end

class AddExternalHostNameToConnections < ActiveRecord::Migration[8.1]
  def change
    add_column :connections, :external_host_name, :string
  end
end

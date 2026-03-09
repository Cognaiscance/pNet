# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.1].define(version: 2026_03_09_224914) do
  create_table "apps", force: :cascade do |t|
    t.string "api_key_digest"
    t.string "app_api_key"
    t.string "app_name", null: false
    t.string "app_uuid", null: false
    t.datetime "created_at", null: false
    t.integer "device_id", null: false
    t.integer "status", default: 0, null: false
    t.datetime "updated_at", null: false
    t.index ["app_uuid"], name: "index_apps_on_app_uuid", unique: true
    t.index ["device_id"], name: "index_apps_on_device_id"
  end

  create_table "connections", force: :cascade do |t|
    t.bigint "connectable_id", null: false
    t.string "connectable_type", null: false
    t.datetime "created_at", null: false
    t.string "host_name", null: false
    t.datetime "last_seen_at"
    t.text "peer_public_key"
    t.string "protocol", default: "udp"
    t.datetime "timeout"
    t.datetime "updated_at", null: false
    t.index ["connectable_type", "connectable_id"], name: "index_connections_on_connectable_type_and_connectable_id"
  end

  create_table "contacts", force: :cascade do |t|
    t.bigint "contact_id", null: false
    t.datetime "created_at", null: false
    t.bigint "owner_id", null: false
    t.datetime "updated_at", null: false
    t.index ["contact_id"], name: "index_contacts_on_contact_id"
    t.index ["owner_id", "contact_id"], name: "index_contacts_on_owner_id_and_contact_id", unique: true
    t.index ["owner_id"], name: "index_contacts_on_owner_id"
  end

  create_table "devices", force: :cascade do |t|
    t.string "alias", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.integer "user_id", null: false
    t.string "uuid", null: false
    t.index ["user_id"], name: "index_devices_on_user_id"
    t.index ["uuid"], name: "index_devices_on_uuid", unique: true
  end

  create_table "ephemeral_key_exchanges", force: :cascade do |t|
    t.integer "connection_id", null: false
    t.datetime "created_at", null: false
    t.text "peer_public_key"
    t.datetime "timeout"
    t.datetime "updated_at", null: false
    t.index ["connection_id"], name: "index_ephemeral_key_exchanges_on_connection_id"
  end

  create_table "key_pairs", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.bigint "owner_id", null: false
    t.string "owner_type", null: false
    t.text "private_key_encrypted", null: false
    t.text "public_key", null: false
    t.datetime "updated_at", null: false
    t.index ["owner_type", "owner_id"], name: "index_key_pairs_on_owner_type_and_owner_id"
  end

  create_table "nodes", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.integer "device_id"
    t.datetime "updated_at", null: false
    t.integer "user_id"
    t.index ["device_id"], name: "index_nodes_on_device_id"
    t.index ["user_id"], name: "index_nodes_on_user_id"
  end

  create_table "users", force: :cascade do |t|
    t.string "alias", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.string "uuid", null: false
    t.index ["uuid"], name: "index_users_on_uuid", unique: true
  end

  add_foreign_key "apps", "devices"
  add_foreign_key "contacts", "users", column: "contact_id"
  add_foreign_key "contacts", "users", column: "owner_id"
  add_foreign_key "devices", "users"
  add_foreign_key "ephemeral_key_exchanges", "connections"
  add_foreign_key "nodes", "devices"
  add_foreign_key "nodes", "users"
end

// MongoDB init script for CVE-2025-14847 demo - creates minimal test data
db = db.getSiblingDB('admin');
db.createUser({ user: "appuser", pwd: "password123", roles: [{ role: "readWrite", db: "testdb" }] });
db = db.getSiblingDB('testdb');
db.users.insertMany([
  { name: "Alice", email: "alice@example.com", role: "admin" },
  { name: "Bob", email: "bob@example.com", role: "user" }
]);
print("MongoDB initialized with test data");

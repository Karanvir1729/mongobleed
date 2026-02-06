// MongoDB Initialization Script
// Creates users and populates with sensitive mock data for CVE-2025-14847 PoC
// DISTINCTIVE MARKERS added for reliable leak detection

// Switch to admin database to create application user
db = db.getSiblingDB('admin');

// Create application user with DISTINCTIVE password for leak detection
db.createUser({
  user: "appuser",
  pwd: "LEAKED_PASSWORD_AppUser456_LEAKED_PASSWORD_AppUser456_LEAKED",
  roles: [
    { role: "readWrite", db: "secretdb" },
    { role: "readWrite", db: "customers" }
  ]
});

// Switch to secretdb
db = db.getSiblingDB('secretdb');

// ============================================================================
// HONEY TOKENS COLLECTION - Long distinctive strings designed to be leaked
// ============================================================================
db.createCollection('honey_tokens');
db.honey_tokens.insertMany([
  {
    name: "primary_honey_token",
    value: "HONEY_TOKEN_PRIMARY_SECRET_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_HONEY_TOKEN_PRIMARY_END",
    description: "LEAKED_HONEY_PRIMARY_LEAKED_HONEY_PRIMARY_LEAKED_HONEY_PRIMARY_END"
  },
  {
    name: "secondary_honey_token", 
    value: "HONEY_TOKEN_SECONDARY_SECRET_YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY_HONEY_TOKEN_SECONDARY_END",
    description: "LEAKED_HONEY_SECONDARY_LEAKED_HONEY_SECONDARY_LEAKED_HONEY_SECONDARY_END"
  },
  {
    name: "database_master_password",
    value: "LEAKED_DB_MASTER_PASSWORD_SuperSecretDBPassword123_LEAKED_DB_MASTER_PASSWORD_END",
    description: "DEMO_PASSWORD_DATABASE_MASTER_DEMO_PASSWORD_DATABASE_MASTER_END"
  },
  {
    name: "api_master_key",
    value: "LEAKED_API_MASTER_KEY_sk_live_XXXXXXXXXXXXXXXXXXXXXXXXXXXX_LEAKED_API_KEY_END",
    description: "DEMO_API_KEY_MASTER_DEMO_API_KEY_MASTER_DEMO_API_KEY_END"
  }
]);

// Create collection with sensitive API keys and secrets - DISTINCTIVE MARKERS
db.createCollection('api_keys');
db.api_keys.insertMany([
  {
    service: "stripe",
    api_key: "LEAKED_STRIPE_KEY_sk_live_XXXXXXXXXXXXXXXXXXXXXXXX_LEAKED_STRIPE_KEY",
    secret_key: "LEAKED_WEBHOOK_SECRET_whsec_XXXXXXXXXXXXXXXXXXXXX_LEAKED_WEBHOOK",
    created_at: new Date(),
    environment: "production",
    marker: "HONEY_TOKEN_STRIPE_HONEY_TOKEN_STRIPE_HONEY_TOKEN_STRIPE_END"
  },
  {
    service: "aws",
    access_key_id: "LEAKED_AWS_AKIAIOSFODNN7EXAMPLE_LEAKED_AWS_KEY",
    secret_access_key: "LEAKED_AWS_SECRET_wJalrXUtnFEMI_K7MDENG_bPxRfiCY_LEAKED_AWS_SECRET_KEY_END",
    region: "us-east-1",
    created_at: new Date(),
    marker: "HONEY_TOKEN_AWS_HONEY_TOKEN_AWS_HONEY_TOKEN_AWS_CREDENTIALS_END"
  },
  {
    service: "openai",
    api_key: "LEAKED_OPENAI_sk-proj-ABCdef123456789XYZ_OPENAI_SECRET_LEAKED_END",
    organization_id: "LEAKED_ORG_org-abc123xyz789_LEAKED_ORG_ID_END",
    created_at: new Date(),
    marker: "HONEY_TOKEN_OPENAI_HONEY_TOKEN_OPENAI_HONEY_TOKEN_OPENAI_END"
  },
  {
    service: "github",
    personal_access_token: "LEAKED_GITHUB_ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx_LEAKED_GITHUB_PAT_END",
    webhook_secret: "LEAKED_GITHUB_WEBHOOK_SECRET_abc123_LEAKED_END",
    created_at: new Date(),
    marker: "HONEY_TOKEN_GITHUB_HONEY_TOKEN_GITHUB_HONEY_TOKEN_GITHUB_END"
  },
  {
    service: "sendgrid",
    api_key: "LEAKED_SENDGRID_SG_xxxxxxxxxxxxxx_yyyyyyyyyyyyyy_LEAKED_SENDGRID_END",
    created_at: new Date(),
    marker: "HONEY_TOKEN_SENDGRID_HONEY_TOKEN_SENDGRID_HONEY_TOKEN_END"
  }
]);

// Create collection with user credentials - DISTINCTIVE MARKERS
db.createCollection('internal_users');
db.internal_users.insertMany([
  {
    username: "john.admin",
    email: "john.admin@company.com",
    password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.GQHqX6E3H9pLZi",
    password_plain: "LEAKED_PASSWORD_JohnAdmin2024_LEAKED_PASSWORD_ADMIN_LEAKED_END",
    role: "superadmin",
    mfa_secret: "LEAKED_MFA_JBSWY3DPEHPK3PXP_LEAKED_MFA_SECRET_END",
    api_token: "LEAKED_JWT_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9_LEAKED_JWT_TOKEN_END",
    marker: "HONEY_TOKEN_ADMIN_USER_HONEY_TOKEN_ADMIN_CREDENTIALS_END"
  },
  {
    username: "sarah.devops",
    email: "sarah.devops@company.com",
    password_hash: "$2b$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi",
    password_plain: "LEAKED_PASSWORD_SarahDevOps789_LEAKED_PASSWORD_DEVOPS_END",
    role: "devops",
    ssh_private_key: "LEAKED_SSH_KEY_BEGIN_OPENSSH_PRIVATE_KEY_b3BlbnNzaC_LEAKED_SSH_END",
    aws_credentials: {
      access_key: "LEAKED_AWS_USER_AKIAI44QH8DH_LEAKED_ACCESS_KEY_END",
      secret_key: "LEAKED_AWS_USER_SECRET_je7MtGbClwBF_LEAKED_SECRET_END"
    },
    marker: "HONEY_TOKEN_DEVOPS_USER_HONEY_TOKEN_DEVOPS_CREDENTIALS_END"
  },
  {
    username: "mike.developer",
    email: "mike.developer@company.com",
    password_hash: "$2b$12$eUz/HYR5T8P.QHqX6E3H9pLZi92IXUNpkjO0rOQ5byMi",
    password_plain: "LEAKED_PASSWORD_MikeDev2024_LEAKED_PASSWORD_DEV_LEAKED_END",
    role: "developer",
    github_token: "LEAKED_GITHUB_USER_ghp_1234567890abcdef_LEAKED_GITHUB_TOKEN_END",
    database_password: "LEAKED_DB_PASSWORD_ProductionDB_Passw0rd_LEAKED_DB_PASS_END",
    marker: "HONEY_TOKEN_DEV_USER_HONEY_TOKEN_DEVELOPER_CREDENTIALS_END"
  }
]);

// Create collection with customer PII
db = db.getSiblingDB('customers');
db.createCollection('profiles');
db.profiles.insertMany([
  {
    customer_id: "CUST-001",
    full_name: "Alice Johnson",
    email: "alice.johnson@email.com",
    phone: "+1-555-0101",
    ssn: "LEAKED_SSN_123-45-6789_LEAKED_SSN_END",
    date_of_birth: new Date("1985-03-15"),
    address: {
      street: "123 Main Street",
      city: "New York",
      state: "NY",
      zip: "10001",
      country: "USA"
    },
    credit_card: {
      number: "LEAKED_CC_4532015112830366_LEAKED_CC_END",
      expiry: "12/27",
      cvv: "123",
      type: "Visa"
    },
    bank_account: {
      routing: "021000021",
      account: "LEAKED_BANK_123456789012_LEAKED_BANK_END"
    },
    marker: "HONEY_TOKEN_CUSTOMER_PII_HONEY_TOKEN_CUSTOMER_DATA_END"
  },
  {
    customer_id: "CUST-002",
    full_name: "Bob Williams",
    email: "bob.williams@email.com",
    phone: "+1-555-0102",
    ssn: "LEAKED_SSN_987-65-4321_LEAKED_SSN_END",
    date_of_birth: new Date("1990-07-22"),
    address: {
      street: "456 Oak Avenue",
      city: "Los Angeles",
      state: "CA",
      zip: "90001",
      country: "USA"
    },
    credit_card: {
      number: "LEAKED_CC_5425233430109903_LEAKED_CC_END",
      expiry: "08/26",
      cvv: "456",
      type: "Mastercard"
    },
    bank_account: {
      routing: "322271627",
      account: "LEAKED_BANK_987654321098_LEAKED_BANK_END"
    },
    marker: "HONEY_TOKEN_CUSTOMER_PII_HONEY_TOKEN_CUSTOMER_DATA_END"
  }
]);

// Create collection with transaction history
db.createCollection('transactions');
db.transactions.insertMany([
  {
    transaction_id: "TXN-20241201-001",
    customer_id: "CUST-001",
    amount: 15750.00,
    currency: "USD",
    type: "wire_transfer",
    destination_account: "LEAKED_IBAN_CH93_0076_2011_6238_5295_7_LEAKED_IBAN_END",
    status: "completed",
    timestamp: new Date(),
    marker: "HONEY_TOKEN_TRANSACTION_HONEY_TOKEN_FINANCIAL_DATA_END"
  },
  {
    transaction_id: "TXN-20241201-002",
    customer_id: "CUST-002",
    amount: 8999.99,
    currency: "USD",
    type: "purchase",
    merchant: "Enterprise Software Inc",
    card_last_four: "9903",
    status: "completed",
    timestamp: new Date(),
    marker: "HONEY_TOKEN_TRANSACTION_HONEY_TOKEN_PURCHASE_DATA_END"
  }
]);

// Create internal secrets collection
db = db.getSiblingDB('secretdb');
db.createCollection('encryption_keys');
db.encryption_keys.insertMany([
  {
    key_id: "master-key-001",
    algorithm: "AES-256-GCM",
    key_material: "LEAKED_ENCRYPTION_KEY_K7gNU3sdo_OL0wNhqoVWhr3g6s1xYv72_LEAKED_KEY_END",
    created_at: new Date(),
    purpose: "database_encryption",
    marker: "HONEY_TOKEN_ENCRYPTION_KEY_HONEY_TOKEN_CRYPTO_END"
  },
  {
    key_id: "jwt-signing-001",
    algorithm: "RS256",
    private_key: "LEAKED_RSA_PRIVATE_KEY_MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn_LEAKED_RSA_END",
    public_key: "-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3\\n-----END PUBLIC KEY-----",
    created_at: new Date(),
    purpose: "jwt_signing",
    marker: "HONEY_TOKEN_JWT_SIGNING_KEY_HONEY_TOKEN_AUTH_END"
  },
  {
    key_id: "backup-encryption-001",
    algorithm: "AES-256-CBC",
    key_material: "LEAKED_BACKUP_KEY_dGhpcyBpcyBhIHNlY3JldCBiYWNrdXA_LEAKED_BACKUP_END",
    iv: "0123456789abcdef",
    created_at: new Date(),
    purpose: "backup_encryption",
    marker: "HONEY_TOKEN_BACKUP_KEY_HONEY_TOKEN_BACKUP_END"
  }
]);

print("==============================================");
print("MongoDB PoC Environment Initialized!");
print("==============================================");
print("Databases created: secretdb, customers");
print("Collections: api_keys, internal_users, profiles, transactions, encryption_keys, honey_tokens");
print("Root user: admin / SuperSecret123!");
print("App user: appuser / LEAKED_PASSWORD_AppUser456...");
print("==============================================");
print("HONEY TOKENS inserted for reliable leak detection!");
print("Look for: LEAKED_, HONEY_TOKEN_, DEMO_PASSWORD_");
print("==============================================");
print("WARNING: This is a VULNERABLE MongoDB instance!");
print("For CVE-2025-14847 testing only!");
print("==============================================");

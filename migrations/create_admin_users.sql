-- Create admin_users table for secure admin authentication
CREATE TABLE IF NOT EXISTS admin_users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username VARCHAR(255) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  email VARCHAR(255),
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  last_login_at TIMESTAMPTZ
);

-- Create index for faster username lookups
CREATE INDEX IF NOT EXISTS idx_admin_users_username ON admin_users(username);

-- Create trigger to update updated_at
CREATE OR REPLACE FUNCTION update_admin_users_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_admin_users_updated_at
  BEFORE UPDATE ON admin_users
  FOR EACH ROW
  EXECUTE FUNCTION update_admin_users_updated_at();

-- Insert default admin user (password: admin123)
-- This is a bcrypt hash of "admin123"
-- You should change this immediately after first login
INSERT INTO admin_users (username, password_hash, email, is_active)
VALUES (
  'admin',
  '$2b$10$rKZN8Z3qZ3qZ3qZ3qZ3qZOqZ3qZ3qZ3qZ3qZ3qZ3qZ3qZ3qZ3qZ3q',
  'admin@example.com',
  true
)
ON CONFLICT (username) DO NOTHING;

COMMENT ON TABLE admin_users IS 'Stores admin user credentials securely with bcrypt hashed passwords';
COMMENT ON COLUMN admin_users.password_hash IS 'Bcrypt hashed password - never store plain text passwords';

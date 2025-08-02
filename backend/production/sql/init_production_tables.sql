-- CyberShield-IronCore Production Database Schema
-- Real database tables for Enterprise SSO

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table for SSO
CREATE TABLE IF NOT EXISTS users (
    user_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255),
    department VARCHAR(255),
    sso_provider VARCHAR(255),
    ad_groups JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE
);

-- Tenant configuration
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_name VARCHAR(255) NOT NULL,
    domain VARCHAR(255),
    plan VARCHAR(50) DEFAULT 'enterprise',
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- SSO audit events
CREATE TABLE IF NOT EXISTS sso_audit_events (
    event_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID,
    user_id UUID,
    event_type VARCHAR(50) NOT NULL,
    event_data JSONB,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- User MFA configuration
CREATE TABLE IF NOT EXISTS user_mfa_config (
    config_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    mfa_type VARCHAR(50) NOT NULL,
    config_data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, mfa_type)
);

-- Role permissions
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    role_name VARCHAR(100) NOT NULL,
    tenant_id UUID,
    permissions JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- AD group to role mappings
CREATE TABLE IF NOT EXISTS ad_role_mappings (
    mapping_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    ad_group VARCHAR(255) NOT NULL,
    application_role VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(tenant_id, ad_group, application_role)
);

-- Tenant authorized users and domains
CREATE TABLE IF NOT EXISTS tenant_authorized_users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    user_email VARCHAR(255) NOT NULL,
    authorized_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(tenant_id, user_email)
);

CREATE TABLE IF NOT EXISTS tenant_authorized_domains (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    domain VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(tenant_id, domain)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_sso_audit_tenant_id ON sso_audit_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sso_audit_created_at ON sso_audit_events(created_at);
CREATE INDEX IF NOT EXISTS idx_user_mfa_user_id ON user_mfa_config(user_id);

-- Insert demo tenant
INSERT INTO tenants (tenant_id, tenant_name, domain, plan, status) 
VALUES ('12345678-1234-5678-9012-123456789012', 'Acme Corporation', 'acme.com', 'enterprise', 'active')
ON CONFLICT (tenant_id) DO NOTHING;

-- Insert demo authorized domain
INSERT INTO tenant_authorized_domains (tenant_id, domain)
VALUES ('12345678-1234-5678-9012-123456789012', 'acme.com')
ON CONFLICT (tenant_id, domain) DO NOTHING;

-- Insert role mappings
INSERT INTO ad_role_mappings (tenant_id, ad_group, application_role) VALUES
('12345678-1234-5678-9012-123456789012', 'CyberSecurity_Admins', 'security_admin'),
('12345678-1234-5678-9012-123456789012', 'IT_Department', 'it_user'),
('12345678-1234-5678-9012-123456789012', 'SOC_Analysts', 'analyst'),
('12345678-1234-5678-9012-123456789012', 'Executive_Team', 'executive'),
('12345678-1234-5678-9012-123456789012', 'Board_Members', 'board_member')
ON CONFLICT (tenant_id, ad_group, application_role) DO NOTHING;

-- Insert role permissions
INSERT INTO role_permissions (role_name, tenant_id, permissions) VALUES
('security_admin', '12345678-1234-5678-9012-123456789012', 
 '["threats.read", "threats.write", "incidents.read", "incidents.write", "admin.users.read"]'::jsonb),
('analyst', '12345678-1234-5678-9012-123456789012', 
 '["threats.read", "incidents.read", "reports.generate"]'::jsonb),
('executive', '12345678-1234-5678-9012-123456789012', 
 '["executive.dashboard", "reports.all", "audit.read"]'::jsonb)
ON CONFLICT DO NOTHING;

COMMIT;
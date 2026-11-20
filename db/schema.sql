CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS users (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL,
 password_hash TEXT NOT NULL, is_active BOOLEAN NOT NULL DEFAULT TRUE, is_owner BOOLEAN NOT NULL DEFAULT FALSE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), last_login_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS roles (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT UNIQUE NOT NULL, description TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS permissions (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), code TEXT UNIQUE NOT NULL, description TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS user_roles (user_id UUID REFERENCES users(id) ON DELETE CASCADE, role_id UUID REFERENCES roles(id) ON DELETE CASCADE, PRIMARY KEY(user_id,role_id));
CREATE TABLE IF NOT EXISTS role_permissions (role_id UUID REFERENCES roles(id) ON DELETE CASCADE, permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE, PRIMARY KEY(role_id,permission_id));
CREATE TABLE IF NOT EXISTS projects (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), title TEXT NOT NULL, slug TEXT UNIQUE NOT NULL, summary TEXT DEFAULT '', description TEXT DEFAULT '', category TEXT DEFAULT 'Other', status TEXT NOT NULL DEFAULT 'Идея', cover_url TEXT DEFAULT '', logo_url TEXT DEFAULT '', lead_id UUID REFERENCES users(id) ON DELETE SET NULL, progress INT NOT NULL DEFAULT 0 CHECK(progress BETWEEN 0 AND 100), is_public BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS project_members (project_id UUID REFERENCES projects(id) ON DELETE CASCADE, user_id UUID REFERENCES users(id) ON DELETE CASCADE, access_level TEXT DEFAULT 'member', PRIMARY KEY(project_id,user_id));
CREATE TABLE IF NOT EXISTS tasks (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), project_id UUID REFERENCES projects(id) ON DELETE SET NULL, parent_id UUID REFERENCES tasks(id) ON DELETE CASCADE, title TEXT NOT NULL, description TEXT DEFAULT '', status TEXT DEFAULT 'К выполнению', priority TEXT DEFAULT 'Средний', assignee_id UUID REFERENCES users(id) ON DELETE SET NULL, due_at TIMESTAMPTZ, created_by UUID REFERENCES users(id) ON DELETE SET NULL, created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS news (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), title TEXT NOT NULL, slug TEXT UNIQUE NOT NULL, excerpt TEXT DEFAULT '', body TEXT DEFAULT '', cover_url TEXT DEFAULT '', published BOOLEAN DEFAULT FALSE, published_at TIMESTAMPTZ, author_id UUID REFERENCES users(id) ON DELETE SET NULL, created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS achievements (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), title TEXT NOT NULL, description TEXT DEFAULT '', date_label TEXT DEFAULT '', sort_order INT DEFAULT 0, is_public BOOLEAN DEFAULT TRUE);
CREATE TABLE IF NOT EXISTS partners (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL, website TEXT DEFAULT '', description TEXT DEFAULT '', logo_url TEXT DEFAULT '', is_public BOOLEAN DEFAULT TRUE);
CREATE TABLE IF NOT EXISTS job_openings (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), title TEXT NOT NULL, department TEXT DEFAULT '', description TEXT DEFAULT '', location TEXT DEFAULT 'Удалённо', is_open BOOLEAN DEFAULT TRUE, created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS contact_messages (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL, email TEXT NOT NULL, subject TEXT DEFAULT '', message TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW(), is_read BOOLEAN DEFAULT FALSE);
CREATE TABLE IF NOT EXISTS channels (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL, kind TEXT DEFAULT 'group', project_id UUID REFERENCES projects(id) ON DELETE CASCADE, created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS channel_members (channel_id UUID REFERENCES channels(id) ON DELETE CASCADE, user_id UUID REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(channel_id,user_id));
CREATE TABLE IF NOT EXISTS messages (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), channel_id UUID REFERENCES channels(id) ON DELETE CASCADE, sender_id UUID REFERENCES users(id) ON DELETE SET NULL, body TEXT NOT NULL, reply_to UUID REFERENCES messages(id) ON DELETE SET NULL, created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS events (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), title TEXT NOT NULL, description TEXT DEFAULT '', starts_at TIMESTAMPTZ NOT NULL, ends_at TIMESTAMPTZ, project_id UUID REFERENCES projects(id) ON DELETE SET NULL, created_by UUID REFERENCES users(id) ON DELETE SET NULL, created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS documents (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), title TEXT NOT NULL, category TEXT DEFAULT 'Общее', body TEXT DEFAULT '', file_url TEXT DEFAULT '', status TEXT DEFAULT 'Черновик', owner_id UUID REFERENCES users(id) ON DELETE SET NULL, created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS notifications (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID REFERENCES users(id) ON DELETE CASCADE, title TEXT NOT NULL, body TEXT DEFAULT '', href TEXT DEFAULT '', read_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS audit_logs (id BIGSERIAL PRIMARY KEY, actor_id UUID REFERENCES users(id) ON DELETE SET NULL, action TEXT NOT NULL, entity_type TEXT DEFAULT '', entity_id TEXT DEFAULT '', details JSONB DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ DEFAULT NOW());
INSERT INTO roles(name,description) VALUES ('Owner','Владелец платформы'),('Administrator','Администратор'),('Employee','Сотрудник') ON CONFLICT(name) DO NOTHING;
INSERT INTO permissions(code,description) VALUES
 ('workspace.view','Доступ к рабочей зоне'),('team.manage','Управление сотрудниками'),('projects.manage','Управление проектами'),('tasks.manage','Управление задачами'),('news.manage','Управление новостями'),('content.manage','Управление публичным контентом'),('messages.use','Использование мессенджера'),('calendar.manage','Управление календарём'),('documents.manage','Управление документами'),('audit.view','Просмотр журнала действий'),('settings.manage','Управление настройками') ON CONFLICT(code) DO NOTHING;
-- Default least-privilege permissions. The owner bypasses role checks; ordinary users receive only workspace access and messaging by default.
INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r CROSS JOIN permissions p
WHERE r.name='Employee' AND p.code IN ('workspace.view','messages.use') ON CONFLICT DO NOTHING;
INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r CROSS JOIN permissions p
WHERE r.name='Administrator' AND p.code IN ('workspace.view','projects.manage','tasks.manage','news.manage','content.manage','messages.use','calendar.manage','documents.manage','audit.view') ON CONFLICT DO NOTHING;

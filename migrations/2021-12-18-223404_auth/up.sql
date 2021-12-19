ALTER TABLE users
ADD COLUMN role VARCHAR NOT NULL DEFAULT 'User';
ALTER TABLE users
    RENAME password TO password_hash;
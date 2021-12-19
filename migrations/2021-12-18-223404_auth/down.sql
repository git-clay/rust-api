ALTER TABLE users DROP COLUMN role,
    DROP COLUMN token,
    RENAME password_hash TO password;
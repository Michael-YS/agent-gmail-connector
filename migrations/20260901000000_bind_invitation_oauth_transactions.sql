ALTER TABLE oauth_transactions ADD COLUMN invitation_token_hash TEXT;
CREATE INDEX oauth_transactions_invitation_hash_idx
    ON oauth_transactions(invitation_token_hash);
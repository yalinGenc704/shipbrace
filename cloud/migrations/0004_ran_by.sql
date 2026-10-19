-- Who started each review: the person who pushed, or who pasted the link.
-- A kept review opens only for that person and the repository's admins.
-- Reviews kept before this have no one recorded and open for admins only.
ALTER TABLE reviews ADD COLUMN ran_by INTEGER;

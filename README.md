# Arun LMS (Cloudflare Workers + D1)

1. `npm install`
2. `npx wrangler login`
3. `npx wrangler d1 create arunlms` -> copy the `database_id` into `wrangler.jsonc`
4. `npm run db:remote` (creates the tables)
5. `npm run deploy`

Workers Builds settings: Build command `npm install`, Deploy command `npx wrangler deploy`.
The first account you sign up becomes admin; promote others under "Manage users".

import { join } from 'path';
import * as dotenv from 'dotenv';

dotenv.config({ path: join(process.cwd(), '.env') });

export default () => ({
  env: process.env.NODE_ENV,
  port: process.env.PORT,
  frontendUrl: process.env.FRONTEND_URL,
  databaseUrl: process.env.DATABASE_URL,
  resetPassLink: process.env.RESET_PASS_LINK,
  jwt: {
    jwt_secret: process.env.JWT_SECRET,
    expires_in: process.env.EXPIRES_IN,
    refresh_token_secret: process.env.REFRESH_TOKEN_SECRET,
    refresh_token_expires_in: process.env.REFRESH_TOKEN_EXPIRES_IN,
    reset_pass_secret: process.env.RESET_PASS_TOKEN,
    reset_pass_token_expires_in: process.env.RESET_PASS_TOKEN_EXPIRES_IN,
  },
});

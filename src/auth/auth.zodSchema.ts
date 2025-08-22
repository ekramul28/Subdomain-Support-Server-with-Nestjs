import { z } from 'zod';

const signupSchema = z.object({
  body: z.object({
    name: z.string().nonempty({ message: 'Name is required!' }),
    email: z.string().nonempty({ message: 'Email is required!' }),
    password: z
      .string()
      .min(6, { message: 'Password must be at least 6 characters!' })
      .max(15, { message: 'Password must be at most 15 characters!' }),
  }),
});
const loginSchema = z.object({
  body: z.object({
    email: z.string().nonempty({ message: 'Email is required!' }),
    password: z.string().nonempty({ message: 'Password is required!' }).min(6).max(15),
  }),
});

export const authSchemas = {
  signupSchema,
  loginSchema,
};

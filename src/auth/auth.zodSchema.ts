import e from 'express';
import { z } from 'zod';

const passwordRegex = /^(?=.*[0-9])(?=.*[!@#$%^&*])/;

const signupSchema = z.object({
  body: z.object({
    email: z.string().nonempty({ message: 'Email is required!' }).email(),

    username: z.string().nonempty({ message: 'Username is required!' }),
    password: z
      .string()
      .min(8, { message: 'Password must be at least 8 characters!' })
      .regex(passwordRegex, {
        message: 'Password must contain at least one number and one special character!',
      }),
    shopNames: z
      .array(z.string().nonempty('Shop name cannot be empty'))
      .min(3, { message: 'You must enter at least 3 shop names' })
      .refine((val) => new Set(val).size === val.length, {
        message: 'Shop names must be unique',
      }),
  }),
});

const loginSchema = z.object({
  body: z.object({
    email: z.string().nonempty({ message: 'Email is required!' }).email(),
    password: z.string().nonempty({ message: 'Password is required!' }).min(6).max(15),
  }),
});

export const authSchemas = {
  signupSchema,
  loginSchema,
};

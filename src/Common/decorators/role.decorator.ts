import { SetMetadata } from '@nestjs/common';
import { UserRole } from 'generated/prisma';

export const Roles = (...roles: UserRole[]) => SetMetadata('roles', roles);

import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';

import { JwtHelperService } from 'src/Common/helper/jwtHelpers';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule } from '@nestjs/config';
import { EmailUtils } from 'src/Common/utils/emil.utils';
import { PrismaService } from 'src/prisma/prisma.service';

@Module({
  imports: [JwtModule.register({}), ConfigModule],
  controllers: [AuthController],
  providers: [AuthService, PrismaService, JwtHelperService, EmailUtils],
  exports: [PrismaService],
})
export class AuthModule {}

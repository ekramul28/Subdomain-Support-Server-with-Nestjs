import {
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
  NotFoundException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { Prisma } from '@prisma/client'; // <-- use @prisma/client, not 'generated/prisma'

enum UserStatus {
  active = 'active',
  inactive = 'inactive',
  // Add other statuses as needed
}
import { JwtHelperService } from 'src/Common/helper/jwtHelpers';
import { EmailUtils } from 'src/Common/utils/emil.utils';
import { PrismaService } from 'src/prisma/prisma.service';

type SignupDto = { name: string; email: string; password: string };
type LoginDto = { email: string; password: string };
type ChangePasswordDto = { oldPassword: string; newPassword: string };
type ResetPasswordDto = { id: string; password: string };

const SALT_ROUNDS = 12;

@Injectable()
export class AuthService {
  constructor(
    private readonly emailUtils: EmailUtils,
    private readonly config: ConfigService,
    private readonly prisma: PrismaService,
    private readonly jwt: JwtHelperService,
  ) {}

  // ---------------------------
  // SIGNUP
  // ---------------------------
  async signupDB(body: SignupDto) {
    const { name, email, password } = body;

    // Optional: enforce password policy here too
    if (!password || password.length < 8) {
      throw new BadRequestException('Password must be at least 8 characters.');
    }

    const hashPass = await bcrypt.hash(password, SALT_ROUNDS);

    try {
      const result = await this.prisma.$transaction(async (tnx) => {
        const userInfo = await tnx.user.create({
          data: {
            name,
            email,
            password: hashPass,
            status: UserStatus.active,
          },
        });

        await tnx.userProfile.create({
          data: {
            email: userInfo.email,
            userId: userInfo.id,
          },
        });

        const accessToken = this.jwt.generateToken(
          { id: userInfo.id, email: userInfo.email, role: userInfo.role },
          this.config.getOrThrow<string>('jwt.jwt_secret'),
          this.config.getOrThrow<string>('jwt.expires_in'),
        );

        const refreshToken = this.jwt.generateToken(
          { id: userInfo.id, email: userInfo.email, role: userInfo.role },
          this.config.getOrThrow<string>('jwt.refresh_token_secret'),
          this.config.getOrThrow<string>('jwt.refresh_token_expires_in'),
        );

        return { accessToken, refreshToken };
      });

      return result;
    } catch (err) {
      // Unique constraint on email
      if (err && err.code === 'P2002') {
        throw new ConflictException('Email already exists.');
      }
      throw new HttpException('Signup failed.', HttpStatus.BAD_REQUEST);
    }
  }

  // ---------------------------
  // LOGIN
  // ---------------------------
  async loginUserDB(payload: LoginDto) {
    const { email, password } = payload;

    // Use findFirstOrThrow for compound filter (email + status)
    const userData = await this.prisma.user.findFirst({
      where: { email, status: UserStatus.active },
    });

    if (!userData) {
      throw new NotFoundException('User not found or inactive.');
    }

    const isCorrectPassword = await bcrypt.compare(password, userData.password);
    if (!isCorrectPassword) {
      throw new HttpException('Incorrect password', HttpStatus.NOT_ACCEPTABLE);
    }

    const accessToken = this.jwt.generateToken(
      { id: userData.id, email: userData.email, role: userData.role },
      this.config.getOrThrow<string>('jwt.jwt_secret'),
      this.config.getOrThrow<string>('jwt.expires_in'),
    );

    const refreshToken = this.jwt.generateToken(
      { id: userData.id, email: userData.email, role: userData.role },
      this.config.getOrThrow<string>('jwt.refresh_token_secret'),
      this.config.getOrThrow<string>('jwt.refresh_token_expires_in'),
    );

    return { accessToken, refreshToken };
  }

  // ---------------------------
  // REFRESH TOKEN
  // ---------------------------
  async refreshTokenDB(token: string) {
    let decoded: { id: string; email: string; role: string };

    try {
      decoded = this.jwt.verifyToken(
        token,
        this.config.getOrThrow<string>('jwt.refresh_token_secret'),
      );
    } catch (err: any) {
      throw new UnauthorizedException(err?.message || 'Invalid refresh token');
    }

    const userData = await this.prisma.user.findFirst({
      where: { email: decoded.email, status: UserStatus.active },
    });

    if (!userData) throw new UnauthorizedException('User not found or inactive.');

    const accessToken = this.jwt.generateToken(
      { id: userData.id, email: userData.email, role: userData.role },
      this.config.getOrThrow<string>('jwt.jwt_secret'),
      this.config.getOrThrow<string>('jwt.expires_in'),
    );

    return { accessToken };
  }

  // ---------------------------
  // CHANGE PASSWORD
  // ---------------------------
  async changePasswordDB(user: { email: string }, payload: ChangePasswordDto) {
    const userData = await this.prisma.user.findFirst({
      where: { email: user.email, status: UserStatus.active },
    });
    if (!userData) throw new NotFoundException('User not found or inactive.');

    const isCorrectPassword = await bcrypt.compare(payload.oldPassword, userData.password);
    if (!isCorrectPassword) {
      throw new HttpException('Incorrect password', HttpStatus.NOT_ACCEPTABLE);
    }

    const hashedPassword = await bcrypt.hash(payload.newPassword, SALT_ROUNDS);

    await this.prisma.user.update({
      where: { id: userData.id },
      data: {
        password: hashedPassword,
        lastPasswordChange: new Date(),
      },
    });

    return { message: 'Password changed successfully!' };
  }

  // ---------------------------
  // FORGOT PASSWORD
  // ---------------------------
  async forgotPasswordDB(payload: { email: string }) {
    const userData = await this.prisma.user.findFirst({
      where: { email: payload.email, status: UserStatus.active },
    });

    // Optional security: always return success to avoid email enumeration
    if (!userData) {
      // return { message: 'If the email exists, a reset link has been sent.' };
      throw new NotFoundException('User not found or inactive.');
    }

    const resetPassToken = this.jwt.generateToken(
      { id: userData.id, email: userData.email, role: userData.role },
      this.config.getOrThrow<string>('jwt.reset_pass_secret'),
      this.config.getOrThrow<string>('jwt.reset_pass_token_expires_in'),
    );

    const baseResetLink = this.config.getOrThrow<string>('RESET_PASS_LINK'); // e.g. http://localhost:3000/reset-password
    const resetPassLink = `${baseResetLink}?userId=${userData.id}&token=${resetPassToken}`;

    await this.emailUtils.sendEmail(
      userData.email,
      'Password reset (valid for a short time)',
      `
        <div>
          <p>Dear ${userData.name || 'User'},</p>
          <p>Click the button below to reset your password:</p>
          <p><a href="${resetPassLink}"><button>Reset Password</button></a></p>
          <p>If you did not request this, you can safely ignore this email.</p>
        </div>
      `,
    );

    return { message: 'Reset link sent to your email.' };
  }

  // ---------------------------
  // RESET PASSWORD
  // ---------------------------
  async resetPasswordDB(token: string, payload: ResetPasswordDto) {
    const user = await this.prisma.user.findFirst({
      where: { id: payload.id, status: UserStatus.active },
    });
    if (!user) throw new NotFoundException('User not found or inactive.');

    let decoded: { id: string; email: string; role: string };
    try {
      decoded = this.jwt.verifyToken(
        token,
        this.config.getOrThrow<string>('jwt.reset_pass_secret'),
      );
    } catch {
      throw new ForbiddenException('Invalid or expired reset token.');
    }

    // Optional: ensure token belongs to the same user
    if (decoded.id !== user.id) {
      throw new ForbiddenException('Invalid reset token for this user.');
    }

    const hashed = await bcrypt.hash(payload.password, SALT_ROUNDS);

    await this.prisma.user.update({
      where: { id: user.id },
      data: { password: hashed, lastPasswordChange: new Date() },
    });

    return { message: 'Password reset successful.' };
  }
}

import { Controller, Post, Req, Res, HttpStatus, UseGuards, UsePipes, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import type { Request, Response } from 'express';
import { successResponse } from 'src/Common/Re-useable/successResponse';
import { ConfigService } from '@nestjs/config';
import { AuthGuard } from 'src/Common/guard/auth.guard';
import { Roles } from 'src/Common/decorators/role.decorator';
import { ZodValidationPipe } from 'src/Common/pipes/zodValidatiionPipe';
import { authSchemas } from './auth.zodSchema';
import { UserRole } from 'generated/prisma';

@Controller('api/auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
  ) {}

  @Post('signup')
  @UsePipes(new ZodValidationPipe(authSchemas.signupSchema as any))
  async signup(@Body() body: any) {
    const result = await this.authService.signupDB(body);
    return successResponse(result, HttpStatus.OK, 'Signup done');
  }

  @Post('login')
  @UsePipes(new ZodValidationPipe(authSchemas.loginSchema as any))
  async loginUser(@Body() body: any, @Res({ passthrough: true }) res: Response) {
    const result = await this.authService.loginUserDB(body);

    const { refreshToken } = result;

    // Send refreshToken in HTTP-only cookie
    res.cookie('refreshToken', refreshToken, {
      secure: this.configService.get('env') === 'production',
      httpOnly: true,
      sameSite: 'lax', // optional, good for subdomain auth
      domain: '.yourdomain.com', // note the leading dot
    });

    return successResponse({ accessToken: result.accessToken }, HttpStatus.OK, 'Login successful');
  }

  @Post('refresh-token')
  async refreshToken(@Req() req: Request) {
    const { refreshToken } = req.cookies;
    const result = await this.authService.refreshTokenDB(refreshToken);
    return successResponse(result, HttpStatus.OK, 'Refresh token sent');
  }

  @Post('change-password')
  @UseGuards(AuthGuard)
  @Roles(UserRole.user, UserRole.admin, UserRole.superAdmin)
  async changePassword(@Req() req: Request, @Body() body: any) {
    const result = await this.authService.changePasswordDB(req.user, body);
    return successResponse(result, HttpStatus.OK, 'Password changed');
  }

  @Post('forgot-password')
  async forgotPassword(@Body() body: { email: string }) {
    const result = await this.authService.forgotPasswordDB(body);
    return successResponse(result, HttpStatus.OK, 'Email sent with reset link');
  }

  @Post('reset-password')
  async resetPassword(@Body() body: { id: string; password: string; token: string }) {
    const { token, ...payload } = body;
    const result = await this.authService.resetPasswordDB(token, payload);
    return successResponse(result, HttpStatus.OK, 'Password reset successfully');
  }
}

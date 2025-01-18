import { IsNotEmpty, MinLength } from 'class-validator';

export class ResetForgottenPasswordDto {
  @IsNotEmpty({ message: 'The otp is required - dto' })
  otp: string;

  @IsNotEmpty({ message: 'newPass empty - dto' })
  @MinLength(4, { message: 'newPass must be > 4 - dto' })
  newPassword: string;

  @IsNotEmpty({ message: 'verifyPass empty - dto' })
  @MinLength(4, { message: 'verifyPass must be > 4 - dto' })
  verifyPassword: string;
}

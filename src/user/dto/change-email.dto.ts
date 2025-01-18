import { IsEmail, IsNotEmpty } from 'class-validator';

export class ChangeEmailDto {
  @IsEmail({}, { message: 'Invalid email - dto' })
  @IsNotEmpty({ message: 'The email is required - dto' })
  email: string;

  @IsNotEmpty({ message: 'The otp is required - dto' })
  otp: string;
}

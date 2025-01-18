import { IsNotEmpty } from 'class-validator';

export class VerifyAccountDto {
  @IsNotEmpty({ message: 'The otp is required' })
  otp: string;
}

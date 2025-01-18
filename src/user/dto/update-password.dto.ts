import { IsNotEmpty, MinLength } from 'class-validator';

export class UpdatePasswordDto {
  currentPassword: string; // for loggedIn user

  @IsNotEmpty({ message: 'New pass is empty - dto' })
  @MinLength(4, { message: 'newPass must be > 4 - dto' })
  newPassword: string;

  @IsNotEmpty({ message: 'VerifyPass is empty - dto' })
  @MinLength(4, { message: 'newPass must be > 4 - dto' })
  verifyPassword: string;

}

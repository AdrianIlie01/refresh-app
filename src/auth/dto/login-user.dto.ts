import { IsNotEmpty } from 'class-validator';

export class LoginUserDto {
  @IsNotEmpty({ message: 'user_name must not be empty' })
  username: string;
  @IsNotEmpty({ message: 'password must not be empty' })
  password: string;
}

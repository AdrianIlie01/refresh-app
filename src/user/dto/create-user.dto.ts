import { IsEmail, IsNotEmpty, MinLength } from "class-validator";

export class CreateUserDto {

  // @IsNotEmpty({message: 'Username must not be empty - dto'})
  username: string;

  @IsNotEmpty({message: 'Password must not be empty - dto'})
  @MinLength(4, {message: 'Password bust be at least 4 characters long -dto'})
  password: string;

  @IsNotEmpty({message: 'Email must not be empty - dto'})
  @IsEmail({}, {message: 'Email form invalid - dto'})
  email: string;

}

import { IsEmail, IsNotEmpty } from "class-validator";

export class SendOtpEmail {

  @IsNotEmpty({message: 'otp must not be empty - dto'})
  otp: string;

  @IsNotEmpty({message: 'username must not be empty - dto'})
  username: string;


  @IsNotEmpty({message: 'email must not be empty - dto'})
  @IsEmail({}, { message: 'Invalid email - dto' })
  email: string;



}

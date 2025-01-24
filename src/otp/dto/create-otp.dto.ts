import { IsEmail, IsNotEmpty, MinLength } from "class-validator";
import { UserEntity } from "../../user/entities/user.entity";
import { Action } from "../../shared/action";

export class CreateOtpDto {

  user: UserEntity;
  action: Action;
  expiresAt: Date
  otp: string

}

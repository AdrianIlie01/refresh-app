import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtService } from "@nestjs/jwt";
import { UserService } from "../user/user.service";
import { UserModule } from "../user/user.module";
import { UserInfoService } from "../user-info/user-info.service";
import { PassportModule } from "@nestjs/passport";
import { LoginGuard } from "./guards/login.guards";
import { LoginStrategy } from "./strategies/login.strategy";

@Module({
  imports: [
    PassportModule,
    UserModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    UserService,
    JwtService,
    UserInfoService,
    LoginStrategy,
    LoginGuard
  ],
})
export class AuthModule {}

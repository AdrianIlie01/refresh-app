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
import { MailService } from "../mail/mail.service";
import { RefreshTokenGuard } from "./guards/refresh-token.guard";
import { TypeOrmModule } from "@nestjs/typeorm";
import { TokenBlackListEntity } from "../token-black-list/entities/token-black-list.entity";

@Module({
  imports: [
    PassportModule,
    UserModule,
    TypeOrmModule.forFeature([TokenBlackListEntity]),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    UserService,
    JwtService,
    UserInfoService,
    MailService,
    LoginStrategy,
    LoginGuard,
    RefreshTokenGuard
  ],
})
export class AuthModule {}

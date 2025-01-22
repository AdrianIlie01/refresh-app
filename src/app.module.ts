import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UserModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import { MailModule } from './mail/mail.module';
import { RoomModule } from './room/room.module';
import { StripeModule } from './stripe/stripe.module';
import { UserInfoModule } from './user-info/user-info.module';
import { VideoModule } from './video/video.module';
import { TypeOrmModule } from "@nestjs/typeorm";
import { UserEntity } from "./user/entities/user.entity";
import { UserInfoEntity } from "./user-info/entities/user-info.entity";
import { RoomEntity } from "./room/entities/room.entity";
import { VideoEntity } from "./video/entities/video.entity";
import { OtpModule } from './otp/otp.module';
import { OtpEntity } from "./otp/entities/otp.entity";
import { JwtModule } from "@nestjs/jwt";
import * as process from "process";
import { ConfigModule } from "@nestjs/config";


@Module({
  imports: [
    ConfigModule.forRoot(),
    TypeOrmModule.forRoot({
      type: 'mysql',
      host: 'localhost',
      port:  3306,
      username: 'livestream',
      password: 'livestream',
      database: 'livestream',
      // host: process.env.HOST,
      // port:  +process.env.DB_PORT,
      // username: process.env.USERNAME,
      // password: process.env.PASSWORD,
      // database: process.env.DATABASE,
      entities: [
        UserEntity,
        UserInfoEntity,
        RoomEntity,
        VideoEntity,
        OtpEntity
      ],
      synchronize: true,
    }),
    JwtModule.register( {
      secret: process.env.SECRET_JWT,
      signOptions: {
        expiresIn: process.env.EXPIRES_IN_JWT,
      }
    }),
    UserModule,
    AuthModule,
    MailModule,
    RoomModule,
    StripeModule,
    UserInfoModule,
    VideoModule,
    OtpModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}

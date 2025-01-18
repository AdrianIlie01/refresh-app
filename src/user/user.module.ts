import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { UserEntity } from "./entities/user.entity";
import { UserInfoEntity } from "../user-info/entities/user-info.entity";
import { TypeOrmModule } from "@nestjs/typeorm";
import { UserInfoService } from "../user-info/user-info.service";
import { UserInfoModule } from "../user-info/user-info.module";

@Module({
  // imports: [TypeOrmModule.forFeature([UserEntity, UserInfoEntity]),],
  controllers: [UserController],
  providers: [UserService, UserInfoService],
})
export class UserModule {}

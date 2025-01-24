import { Module } from '@nestjs/common';
import { TokenBlackListService } from './token-black-list.service';
import { TokenBlackListController } from './token-black-list.controller';

@Module({
  controllers: [TokenBlackListController],
  providers: [TokenBlackListService],
})
export class TokenBlackListModule {}

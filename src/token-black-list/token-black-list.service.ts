import { Injectable } from '@nestjs/common';
import { CreateTokenBlackListDto } from './dto/create-token-black-list.dto';
import { UpdateTokenBlackListDto } from './dto/update-token-black-list.dto';
import { TokenBlackListEntity } from "./entities/token-black-list.entity";
import { LessThan } from "typeorm";

@Injectable()
export class TokenBlackListService {

  async removeExpiredTokens(): Promise<void> {
    const currentTime = new Date();
    await TokenBlackListEntity.delete({
      expires_at: LessThan(currentTime),
    });
  }

  create(createTokenBlackListDto: CreateTokenBlackListDto) {
    return 'This action adds a new tokenBlackList';
  }

  findAll() {
    return `This action returns all tokenBlackList`;
  }

  findOne(id: number) {
    return `This action returns a #${id} tokenBlackList`;
  }

  update(id: number, updateTokenBlackListDto: UpdateTokenBlackListDto) {
    return `This action updates a #${id} tokenBlackList`;
  }

  remove(id: number) {
    return `This action removes a #${id} tokenBlackList`;
  }
}

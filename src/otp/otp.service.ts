import { BadRequestException, Injectable } from "@nestjs/common";
import { UpdateOtpDto } from "./dto/update-otp.dto";
import { OtpEntity } from "./entities/otp.entity";
import { Action } from "../shared/action";
import { UserEntity } from "../user/entities/user.entity";

@Injectable()
export class OtpService {
 async create(user: UserEntity, action: Action, expiresAt, otp) {
    try {
      const twoFaToken = await new OtpEntity();
      twoFaToken.user = user;
      twoFaToken.action = action;
      twoFaToken.expires_at = expiresAt;
      twoFaToken.otp = otp;

      return await twoFaToken.save();
    } catch (e) {
      throw new BadRequestException(e.message)
    }
 }

 async findAllForUser(id: string) {
    try {
      return await OtpEntity.find({
        where: {user: {id: id}},
      });
    } catch (e) {
      throw new BadRequestException(e.message)
    }  }

 async findOne(id: string) {
    try {
      return await OtpEntity.findOne({
        where: {user: {id: id}, action: Action.Login},
      });
    } catch (e) {
      throw new BadRequestException(e.message)
    }
  }

  async findOneById(id: string) {
    try {
      return await OtpEntity.findOne({
        where: {user: {id: id}},
      });
    } catch (e) {
      throw new BadRequestException(e.message)
    }
  }

  async findOneByOtp(id: string, otp: string) {
    try {
      return await OtpEntity.findOne({
        where: {
          user: {id: id},
          otp: otp,
        },
        relations: ['user'],
      });
    } catch (e) {
      throw new BadRequestException(e.message)
    }
  }

  async findOneForLogin(id: string) {
    try {
      return await OtpEntity.findOne({
        where: {user: {id: id}, action: Action.Login},
      });
    } catch (e) {
      throw new BadRequestException(e.message)
    }
  }

  update(id: number, updateOtpDto: UpdateOtpDto) {
    return `This action updates a #${id} otp`;
  }

  remove(id: number) {
    return `This action removes a #${id} otp`;
  }
}

import { BadRequestException, Injectable } from "@nestjs/common";
import { CreateUserInfoDto } from './dto/create-user-info.dto';
import { UpdateUserInfoDto } from './dto/update-user-info.dto';
import { UserInfoEntity } from "./entities/user-info.entity";
import { UserEntity } from "../user/entities/user.entity";

@Injectable()
export class UserInfoService {
  async create(createUserInfoDto: CreateUserInfoDto, id: string) {
    try {
      const { phone, person_region} = createUserInfoDto;

      const user = await UserEntity.findOneBy({id: id});

      const userInfo = new UserInfoEntity();
      userInfo.phone = phone;
      userInfo.person_region = person_region;

      if (user) {
        console.log('m');
       userInfo.user = user;
       return await userInfo.save();



      } else {
        return  new BadRequestException({}, {description: 'nu exista user cu acel id'})
      }


    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  async findAll() {
    try {
      const info = await UserInfoEntity.find({relations: ['user']});
      return info;
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  async findOne(id: string) {
    try {
      const info = await UserInfoEntity.findOneBy({id: id});
      return info;
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  async findOneByUser(id: string) {
    try {
      const user = await UserEntity.findOneBy({id: id})
      console.log(user);
      if (user) {
        const info = await UserInfoEntity.findOne({
          where:{user: {id: user.id}}
        });
        return info;
      }

      throw new BadRequestException('user or user-info not found with the provided id');
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  async update(id: string, updateUserInfoDto: UpdateUserInfoDto) {
    try {
      const info = await UserInfoEntity.findOneBy({user:{id: id}});

      const {person_region, phone} = updateUserInfoDto;

      console.log(info);
      console.log(person_region);
      console.log(typeof person_region);

      typeof person_region !== 'undefined'
      ? info.person_region = person_region
      : info.person_region = info.person_region

      typeof phone !== 'undefined'
        ? info.phone = phone
        : info.phone = info.phone

      await info.save();

      console.log(info);

      return {'message': 'user-info updated'};
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  async findByUserId(user: UserEntity) {
    try {
      const userInfo = await UserInfoEntity.findOne({
        where: { user: { id: user.id } },
        relations: ['user'],
      });

      return userInfo;
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  async remove(id: string) {
    try {
      const info = await UserInfoEntity.findOneBy({id: id});
      return info.remove();
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }
}

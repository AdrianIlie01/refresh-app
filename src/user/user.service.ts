import { BadRequestException, Injectable } from "@nestjs/common";
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UserEntity } from "./entities/user.entity";
import * as bcrypt from 'bcrypt';
import { UserInfoService } from "../user-info/user-info.service";
import { UserInfoEntity } from "../user-info/entities/user-info.entity";

@Injectable()
export class UserService
{
  constructor(
   private UserInfoService: UserInfoService,
  ) {}
  async create(createUserDto: CreateUserDto) {
    try{

      const { username, password, email } = createUserDto;

      const user = new UserEntity();

      user.username = username;
      user.password = await bcrypt.hash(password, 10);
      user.email = email;

      const savedUser = await user.save();

      let data = {};

      if (savedUser) {
        const {password, refresh_token, ...restData} = savedUser;
        data = restData;
      }


      return data;

    } catch (e) {
      throw new BadRequestException(e.message)
    }
  }

  async findAll() {
    try{

      return await UserEntity.find();

    } catch (e) {
      throw new BadRequestException(e.message)
    }  }

  async findOne(id: string) {
    try{
      const  user = await UserEntity.findOne({
        where: {id: id}
      });

      const { password,  refresh_token, ...data } = user;

      return data;

    } catch (e) {
      throw new BadRequestException(e.message)
    }  }

  async update(id: string, updateUserDto: UpdateUserDto) {
    try{
      const {username} = updateUserDto;

      const user = await UserEntity.findOne({where: { id: id }});
      const initialUsername = user.username;


      typeof username !== 'undefined'
        ? (user.username = username)
        : (user.username = initialUsername);

      return await user.save();

    } catch (e) {
      throw new BadRequestException(e.message)
    }  }

  async remove(id: string) {
    try{

    } catch (e) {
      throw new BadRequestException(e.message)
    }
  }
}

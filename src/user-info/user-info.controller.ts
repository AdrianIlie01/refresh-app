import { Controller, Get, Post, Body, Patch, Param, Delete, HttpStatus, Res } from "@nestjs/common";
import { UserInfoService } from './user-info.service';
import { CreateUserInfoDto } from './dto/create-user-info.dto';
import { UpdateUserInfoDto } from './dto/update-user-info.dto';

@Controller('user-info')
export class UserInfoController {
  constructor(private readonly userInfoService: UserInfoService) {}

  @Post(':id')
  async create(
    @Res() res,
    @Body() createUserInfoDto: CreateUserInfoDto,
    @Param('id') id: string)
{
    try {
      const userInfo = await this.userInfoService.create(createUserInfoDto, id);
      return res.status(HttpStatus.OK).json(userInfo);
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }

  }

  @Get()
  async findAll(
    @Res() res
  ) {
    try {
      const info = await this.userInfoService.findAll();
      return res.status(HttpStatus.OK).json(info);
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

  @Get(':id')
  async findOne(
    @Res() res,
    @Param('id') id: string)
  {
    try {
      const info = await this.userInfoService.findOne(id);
      return res.status(HttpStatus.OK).json(info);
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

  @Patch(':id')
  async update(
    @Res() res,
    @Param('id') id: string,
    @Body() updateUserInfoDto: UpdateUserInfoDto)
  {
    try {
      const info = await this.userInfoService.update(id, updateUserInfoDto);
      return res.status(HttpStatus.OK).json(info);
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

  @Delete(':id')
  async remove(
    @Res() res,
    @Param('id') id: string) {
    try {
      const info = await this.userInfoService.remove(id);
      return res.status(HttpStatus.OK).json(info);
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }
}

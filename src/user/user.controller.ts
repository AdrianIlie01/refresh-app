import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  BadRequestException,
  HttpStatus,
  Res
} from "@nestjs/common";
import { UserService } from './user.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post()
 async create(
    @Res() res,
    @Body() createUserDto: CreateUserDto) {
    try {
      const user = await this.userService.create(createUserDto);
      return res.status(HttpStatus.OK).json(user);
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

  @Get()
  async  findAll(
    @Res() res,
  ) {
    try {
      const users = await this.userService.findAll();
      return res.status(HttpStatus.OK).json(users);
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

  @Get(':id')
  async findOne(
    @Res() res,
    @Param('id') id: string
  ) {
    try {
      const user = await this.userService.findOne(id);
      return res.status(HttpStatus.OK).json(user);
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

  @Patch(':id')
  async update(
    @Res() res,
    @Param('id') id: string,
    @Body() updateUserDto: UpdateUserDto
  ) {
    try {
      const user = await this.userService.update(id, updateUserDto);
      return res.status(HttpStatus.OK).json(user);
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

  @Delete(':id')
  async remove(
    @Res() res,
    @Param('id') id: string
  ) {
    try {
      const user = await this.userService.remove(id);
      return res.status(HttpStatus.OK).json(user);
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }
}

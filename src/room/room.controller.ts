import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Res, HttpStatus } from "@nestjs/common";
import { RoomService } from './room.service';
import { CreateRoomDto } from './dto/create-room.dto';
import { UpdateRoomDto } from './dto/update-room.dto';
import { LoginGuard } from "../auth/guards/login.guards";
import { RolesGuard } from "../auth/guards/roles.guard";
import { Roles } from "../auth/decorators/roles.decorator";

@Controller('room')
export class RoomController {
  constructor(private readonly roomService: RoomService) {}

  @Post()
  create(@Body() createRoomDto: CreateRoomDto) {
    return this.roomService.create(createRoomDto);
  }

  // @UseGuards(LoginGuard)
  // @UseGuards(RolesGuard)
  // @Roles('admin')
  @Get('get-video/:name')
  async getVideo(@Res() res, @Param('name') name: string) {
    try {
      // res.setHeader('Content-Type', 'video/mp4');
      res.sendFile(name, { root: 'uploaded-videos' });
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

  @Get()
  findAll() {
    return this.roomService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.roomService.findOne(+id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateRoomDto: UpdateRoomDto) {
    return this.roomService.update(+id, updateRoomDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.roomService.remove(+id);
  }
}

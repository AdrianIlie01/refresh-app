import { Controller, Get, Post, Body, Patch, Param, Delete } from '@nestjs/common';
import { TokenBlackListService } from './token-black-list.service';
import { CreateTokenBlackListDto } from './dto/create-token-black-list.dto';
import { UpdateTokenBlackListDto } from './dto/update-token-black-list.dto';

@Controller('token-black-list')
export class TokenBlackListController {
  constructor(private readonly tokenBlackListService: TokenBlackListService) {}

  @Post()
  create(@Body() createTokenBlackListDto: CreateTokenBlackListDto) {
    return this.tokenBlackListService.create(createTokenBlackListDto);
  }

  @Get()
  findAll() {
    return this.tokenBlackListService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.tokenBlackListService.findOne(+id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateTokenBlackListDto: UpdateTokenBlackListDto) {
    return this.tokenBlackListService.update(+id, updateTokenBlackListDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.tokenBlackListService.remove(+id);
  }
}

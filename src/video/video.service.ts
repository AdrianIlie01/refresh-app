import { BadRequestException, Injectable } from "@nestjs/common";
import { UpdateVideoDto } from './dto/update-video.dto';
import { UserEntity } from "../user/entities/user.entity";
import { VideoEntity } from "./entities/video.entity";
import { Express } from 'express'

@Injectable()
export class VideoService {
 async create(id, file: Express.Multer.File) {
   try{
     const user = await UserEntity.findOneBy({id: id});

   if (file) {
     const video = await new VideoEntity();
     video.name = file.filename;
     video.user = user;
    return  await video.save();
   }

   } catch (e) {
     throw new BadRequestException(e.message)
   }
 }

  async findAll() {
    try{

    } catch (e) {
      throw new BadRequestException(e.message)
    }
 }

  async findOne(id: number) {
    try{

    } catch (e) {
      throw new BadRequestException(e.message)
    }
 }

  async update(id: number, updateVideoDto: UpdateVideoDto) {
    try{

    } catch (e) {
      throw new BadRequestException(e.message)
    }
 }

  async remove(id: number) {
    try{

    } catch (e) {
      throw new BadRequestException(e.message)
    }
 }
}

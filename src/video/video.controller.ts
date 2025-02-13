import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Res,
  HttpStatus,
  UseInterceptors,
  UploadedFile, Query
} from "@nestjs/common";
import { VideoService } from './video.service';
import { UpdateVideoDto } from './dto/update-video.dto';
import { join } from "path";
import { unlinkSync } from "fs";
import { VideoInterceptor } from "./video-interceptor/video.interceptor";
import { videoPath } from "../shared/video-path";
import { Express } from 'express'

@Controller('video')
export class VideoController {
  constructor(private readonly videoService: VideoService) {}

  @Post(':id')
  @UseInterceptors(VideoInterceptor)
  async create(
    @Res() res,
    @Param('id') id: string,
    @Body() body: any,
    @UploadedFile() file: Express.Multer.File,
  ) {
    try {

      console.log(file);
      console.log('roomName:');
      console.log(body.room_name);

      console.log(typeof body.room_name);

      if (!file) {
        return res.status(HttpStatus.BAD_REQUEST).json({
          message: 'No file uploaded.',
        });
      }

      const video = await this.videoService.create(id, file, body);
      return res.status(HttpStatus.CREATED).json(video);
    } catch (e) {
      if (file) {
        const filePath = join(videoPath, file.filename);
        await unlinkSync(filePath);
      }
      return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        message: 'Error processing file.',
        error: e.message,
      });
    }
  }

  @Get()
  async findAll(
    @Res() res,
  ) {
    try {
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
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

  @Patch(':id')
  async update(
    @Res() res,
    @Param('id') id: string, @Body() updateVideoDto: UpdateVideoDto) {
    try {
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

  @Delete(':id')
  async remove(
    @Res() res,
    @Param('id') id: string) {
    try {
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }
}

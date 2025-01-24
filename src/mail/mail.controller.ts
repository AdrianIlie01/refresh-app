import { Controller, Get, Post, Body, Patch, Param, Delete, HttpStatus, Res } from "@nestjs/common";
import { MailService } from './mail.service';
import { SendOtpEmail } from './dto/send-otp-email';
import { UpdateMailDto } from './dto/update-mail.dto';

@Controller('mail')
export class MailController {
  constructor(private readonly mailService: MailService) {}

  @Post()
async create( @Res() res, @Body() createMailDto: SendOtpEmail) {
    try {
      const email = await this.mailService.sendMail(createMailDto);
      return res.status(HttpStatus.OK).json(email);
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

}

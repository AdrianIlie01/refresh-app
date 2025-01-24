import { Module } from '@nestjs/common';
import { MailService } from './mail.service';
import { MailController } from './mail.controller';
import { MAILER_TRANSPORTER } from "../shared/mail.constants";
import * as nodemailer from 'nodemailer';
import * as process from "process";

@Module({
  imports: [],
  controllers: [MailController],
  providers: [
    MailService,
    // {
    //   provide: MAILER_TRANSPORTER,
    //   useFactory: () => {
    //     // Configurare nodemailer transporter
    //     return nodemailer.createTransport({
    //       host: process.env.EMAIL_HOST,
    //       port:  process.env.EMAIL_PORT,
    //       secure: false, // `true` pentru port 465, `false` pentru 587
    //       auth: {
    //         user:  process.env.EMAIL_USERNAME,
    //         pass:  process.env.EMAIL_PASSWORD,
    //       },
    //     });
    //   },
    // },
  ],
})
export class MailModule {}

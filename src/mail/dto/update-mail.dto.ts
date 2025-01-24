import { PartialType } from '@nestjs/mapped-types';
import { SendOtpEmail } from './send-otp-email';

export class UpdateMailDto extends PartialType(SendOtpEmail) {}

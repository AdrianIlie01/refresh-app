import { Controller, Get, Post, Body, Patch, Param, Delete, Res, HttpStatus, Req, UseGuards } from "@nestjs/common";
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { LoginUserDto } from "./dto/login-user.dto";
import { Action } from "../shared/action";
import { json } from "express";
import { LoginGuard } from "./guards/login.guards";
import * as process from "process";
import { RefreshTokenGuard } from "./guards/refresh-token.guard";

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  async login(
    @Res() res,
    @Req() req,
    @Body() loginUserDto: LoginUserDto
  ) {
    try {
      const login: any = await this.authService.login(loginUserDto, res);
      return res.status(200).json(login);
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

  @Post('generate-otp/:id')
  async generateOtp(
    @Res() res,
    @Param('id') id: string,
    @Body()  body: {action: Action}
  ) {
    try {
      const generateOtp = await this.authService.generateSendOtp(id, body.action);
      return res.status(HttpStatus.OK).json(generateOtp);
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

  @Post('otp-verify/:id')
  async otp2(
    @Res() res,
    @Req() req,
    @Param('id') id: string,
    @Body() body: {action: Action, otp: string},
  ) {
    try {
      const verify: any = await this.authService.verifyOtpLogin(id, body.otp, body.action, res, req);
      return res.status(HttpStatus.OK).json(verify);
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

  @UseGuards(LoginGuard)
  @UseGuards(RefreshTokenGuard)
  @Post('refresh-token')
  async refreshToken(@Req() req, @Res() res) {
    try {
      const { accessToken } = await this.authService.refreshToken(req);
      return res.status(HttpStatus.OK).json({accessToken});
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

  @UseGuards(LoginGuard)
  @Post('verify')
  async verify(
    @Res() res,
    @Req() req,
  ) {
    try {
      return res.status(200).json('works protected');
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

  @UseGuards(LoginGuard)
  @Post('logout')
  async logout(
    @Res() res,
    @Req() req,
  ) {
    try {
      const logout = await this.authService.logout(res, req);
      return res.status(200).json(logout);
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

}

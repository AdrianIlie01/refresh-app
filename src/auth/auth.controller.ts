import { Controller, Get, Post, Body, Patch, Param, Delete, Res, HttpStatus, Req, UseGuards } from "@nestjs/common";
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { LoginUserDto } from "./dto/login-user.dto";
import { Action } from "../shared/action";
import { json } from "express";
import { LoginGuard } from "./guards/login.guards";
import * as process from "process";

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('verify-user')
  async verifyUser(
    @Res() res,
    @Body() loginUserDto: LoginUserDto
  ) {
    try {
      const login = await this.authService.validateUser(loginUserDto);
      return res.status(HttpStatus.OK).json(login);
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

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
      const generateOtp = await this.authService.generateOtp(id, body.action);
      return res.status(HttpStatus.OK).json(generateOtp);
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

  @Post('otp-verify/:id')
  async otp2(
    @Res() res,
    @Param('id') id: string,
    @Body() body: {action: Action, otp: string},
  ) {
    try {
      const verify: any = await this.authService.verifyOtp(id, body.otp, body.action);

      if (verify) {
        res.cookie('access_token', verify.access_token, {
          httpOnly: true, // Protejează cookie-ul de atacuri XSS
          secure: process.env.NODE_ENV === 'production', // Folosește ternary operator pentru a seta secure
          maxAge: 3600 * 1000, // 1 oră
        });

        res.cookie('refresh_token', verify.refresh_token, {
          httpOnly: true, // Protejează cookie-ul de atacuri XSS
          secure: process.env.NODE_ENV === 'production', // Folosește ternary operator pentru a seta secure
          maxAge: 7 * 24 * 3600 * 1000, // 7 zile
        });
      }
      return res.status(200).json({ message: 'Login successful' });

      // return res.status(HttpStatus.OK).json(verify);
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

  @Post('refresh-token')
  async refreshToken(@Req() req, @Res() res) {
    try {
    const refreshToken = req.cookies['refresh_token'];

    if (!refreshToken) {
      return res.status(HttpStatus.BAD_REQUEST).json({
        message: 'Refresh token missing',
      });
    }
      // Verificăm refresh token-ul și generăm un nou access token
      const { accessToken } = await this.authService.refreshToken(refreshToken);

      console.log('contrl accesT');
      console.log(accessToken);

      return res.status(HttpStatus.OK).json({accessToken});
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

}

import { Controller, Post, Body, Param, Res, HttpStatus, Req, UseGuards } from "@nestjs/common";
import { AuthService } from './auth.service';
import { LoginUserDto } from "./dto/login-user.dto";
import { Action } from "../shared/action";
import { LoginGuard } from "./guards/login.guards";
import * as process from "process";
import { RefreshTokenGuard } from "./guards/refresh-token.guard";
import { Roles } from "./decorators/roles.decorator";
import { RolesGuard } from "./guards/roles.guard";

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
      res.clearCookie('access_token', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: +process.env.ACCES_TOKEN_EXPIRES_IN,
      });

      res.clearCookie('refresh_token', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: +process.env.REFRESH_TOKEN_EXPIRES_IN,

    });

      const login: any = await this.authService.login(loginUserDto);

      if (login.access_token) {
        res.cookie('access_token', login.access_token, {
          httpOnly: true, // Protejează cookie-ul de atacuri XSS
          secure: process.env.NODE_ENV === 'production', // Folosește ternary operator pentru a seta secure
          maxAge: parseInt(process.env.ACCES_TOKEN_EXPIRES_IN)
        });
      }

      if (login.refresh_token) {
        res.cookie('refresh_token', login.refresh_token, {
          httpOnly: true, // Protejează cookie-ul de atacuri XSS
          secure: process.env.NODE_ENV === 'production', // Folosește ternary operator pentru a seta secure
          maxAge: parseInt(process.env.REFRESH_TOKEN_EXPIRES_IN)
        });
      }

      return res.status(HttpStatus.OK).json(login);
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
      const accessTokenCookie = req.cookies['access_token'];

      const verify: any = await this.authService.verifyOtpLogin(id, body.otp, body.action, accessTokenCookie);

      if (verify.access_token) {
        res.cookie('access_token', verify.access_token, {
          httpOnly: true, // Protejează cookie-ul de atacuri XSS
          secure: process.env.NODE_ENV === 'production', // Folosește ternary operator pentru a seta secure
          maxAge: parseInt(process.env.ACCES_TOKEN_EXPIRES_IN)
        });
      }

      if (verify.refresh_token) {
        res.cookie('refresh_token', verify.refresh_token, {
          httpOnly: true, // Protejează cookie-ul de atacuri XSS
          secure: process.env.NODE_ENV === 'production', // Folosește ternary operator pentru a seta secure
          maxAge: parseInt(process.env.REFRESH_TOKEN_EXPIRES_IN)
        });
      }
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
      const refreshToken = req.cookies['refresh_token'];
      const { access_token } = await this.authService.refreshToken(refreshToken);
      return res.status(HttpStatus.OK).json({access_token});
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

  @UseGuards(RolesGuard)
  @Roles('user')
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
      const accessToken = req.cookies['access_token'];
      const refreshToken = req.cookies['refresh_token'];

      const logout = await this.authService.logout(accessToken, refreshToken);
      res.clearCookie('access_token');
      res.clearCookie('refresh_token');

      return res.status(200).json(logout);
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

}

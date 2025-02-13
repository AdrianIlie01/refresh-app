import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpStatus,
  Param,
  Post,
  Req,
  Res,
  UseGuards
} from "@nestjs/common";
import { AuthService } from "./auth.service";
import { LoginUserDto } from "./dto/login-user.dto";
import { Action } from "../shared/action";
import { LoginGuard } from "./guards/login.guards";
import * as process from "process";
import { RefreshTokenGuard } from "./guards/refresh-token.guard";
import { Roles } from "./decorators/roles.decorator";
import { RolesGuard } from "./guards/roles.guard";
import { TokenBlackListEntity } from "../token-black-list/entities/token-black-list.entity";

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    ) {}

  @Post('login')
  async login(
    @Res() res,
    @Req() req,
    @Body() loginUserDto: LoginUserDto
  ) {
    try {

      if (req.cookies['access_token']) {
        res.clearCookie('access_token', {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          maxAge: +process.env.ACCESS_TOKEN_EXPIRES_IN,
        });
      }

      if (req.cookies['refresh_token']) {
        res.clearCookie('refresh_token', {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          maxAge: +process.env.REFRESH_TOKEN_EXPIRES_IN,
        });
      }

      const login: any = await this.authService.login(loginUserDto);

      console.log('login');
      console.log(login);

      if (login.access_token) {
        console.log('parseInt(process.env.ACCESS_TOKEN_EXPIRES_IN)');
        console.log(parseInt(process.env.ACCESS_TOKEN_EXPIRES_IN));
        res.cookie('access_token', login.access_token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          maxAge: parseInt(process.env.ACCESS_TOKEN_EXPIRES_IN)
        });
        console.log('cookie set');
        console.log(res.cookie.access_token);
      }

      if (login.access_token_2fa) {
        console.log('ok ?');

        console.log(login.access_token_2fa.access_token);



        console.log('efore setting access token for 2fa');

        res.cookie('access_token', login.access_token_2fa.access_token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          maxAge: parseInt(process.env.ACCESS_TOKEN_EXPIRES_IN)
        });

        console.log('cookie set with 2fa');


      }

      if (login.refresh_token) {

        res.cookie('refresh_token', login.refresh_token, {
          httpOnly: true, // Protejează cookie-ul de atacuri XSS
          secure: process.env.NODE_ENV === 'production', // Folosește ternary operator pentru a seta secure
          maxAge: parseInt(process.env.REFRESH_TOKEN_EXPIRES_IN)
        });

        console.log(res.cookie.refresh_token);
        console.log('cookie set');

      }

      console.log('finish login');

      return res.status(HttpStatus.OK).json(login);
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

  @Post('generate-otp/:id')
  async generateOtp(
    @Res() res,
    @Param('id') id: string,
    // @Body()  body: {action: Action}
  ) {
    try {
      //todo asta e functie folosita pt a trimtie otp pt login, deci nu mai punem pe body action

      // const generateOtp = await this.authService.generateSendOtp(id, body.action);
      const generateOtp = await this.authService.generateSendOtp(id, Action.Login);
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
    @Body() body: { otp: string},
  ) {
    try {
      const accessTokenCookie = req.cookies['access_token'];

      const verify: any = await this.authService.verifyOtpLogin(id, body.otp, Action.Login, accessTokenCookie);

      if (verify.access_token) {
        res.cookie('access_token', verify.access_token, {
          httpOnly: true, // Protejează cookie-ul de atacuri XSS
          secure: process.env.NODE_ENV === 'production', // Folosește ternary operator pentru a seta secure
          maxAge: parseInt(process.env.ACCESS_TOKEN_EXPIRES_IN)
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

  @UseGuards(RefreshTokenGuard)
  @Post('refresh-token')
  async refreshToken(@Req() req, @Res() res) {
    try {
      const refreshToken = req.cookies['refresh_token'];
      const { access_token } = await this.authService.refreshToken(refreshToken);

      res.cookie('access_token',access_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: parseInt(process.env.ACCESS_TOKEN_EXPIRES_IN)
      });

      return res.status(HttpStatus.OK).json({access_token});
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

  @Post('check-token')
  async checkRefreshToken(@Req() req, @Res() res) {
    try {
      const refreshToken = req.cookies['refresh_token'];

      if (!refreshToken) {
        return res.status(HttpStatus.OK).json({ message: false });
      }
      const blacklistedToken = await TokenBlackListEntity.findOne({
        where: { token: refreshToken },
      });

      if (blacklistedToken) {
        throw new BadRequestException('Refresh token is blacklisted');
      }

      return res.status(HttpStatus.OK).json({ message: true });
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


      if (req.cookies['access_token']) {
        res.clearCookie('access_token');
      }

      if (req.cookies['refresh_token']) {
        res.clearCookie('refresh_token');
      }

      return res.status(200).json(logout);
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

  @Get('is-authenticated')
  async checkLoggedIn(
    @Res() res,
    @Req() req,
  ) {
    try {
      // if (!req.user) {
      //   throw new UnauthorizedException('Token invalid');
      // }
//todo
// aici trebuia sa validez cookie-ul daca e valid, daca u e black lsited la fel ca in LoginStrategy



      const jwt1 = req.cookies.access_token;
      const jwt2 = req.cookies.refresh_token;

      if (jwt1 && jwt2) {
        return res.status(HttpStatus.OK).json(true);
      } else {
        return res.status(HttpStatus.OK).json(false);
      }

      // return res.status(200).json(req.user);
    } catch (e) {
      return res.status(HttpStatus.BAD_REQUEST).json(e);
    }
  }

}

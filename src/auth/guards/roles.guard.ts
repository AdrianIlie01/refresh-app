import {
  BadRequestException,
  CanActivate,
  ExecutionContext,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector, private jwtService: JwtService) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    try {
      const roles = this.reflector.get<string[]>('roles', context.getHandler());

      const request = context.switchToHttp().getRequest();
      const authHeader = request.headers.authorization;

      const token = authHeader.split(' ')[1];
      const decodedToken = await this.jwtService.decode(token);
      const userRole = decodedToken['roles'];

      return roles.includes(userRole);
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }
}

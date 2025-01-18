import { IsEnum, IsNotEmpty } from 'class-validator';
import { Role } from '../../shared/role';

export class ChangeRoleDto {
  @IsNotEmpty({ message: 'The username is required - dto' })
  username: string;

  @IsEnum(Role, { message: 'Invalid status value - dto' })
  role: Role;
}

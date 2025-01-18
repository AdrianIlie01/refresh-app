import {
  BaseEntity,
  Column,
  CreateDateColumn,
  Entity, JoinColumn,
  ManyToOne,
  PrimaryColumn,
  UpdateDateColumn
} from "typeorm";
import { UserEntity } from '../../user/entities/user.entity';
import { Action } from '../../shared/action';

@Entity('otp')
export class OtpEntity extends BaseEntity {

  @PrimaryColumn( 'uuid')
  id: string;

  @Column({ type: 'varchar', length: 255 })
  token: string;

  @Column({ type: 'enum', enum: Action })
  action: Action;

  @Column({ type: 'varchar', length: 6 })
  otp: string;

  @Column({ type: 'datetime' })
  expires_at: Date;

  @ManyToOne(() => UserEntity, (user: UserEntity) => user.otp)
  @JoinColumn({ name: 'user', referencedColumnName: 'id' })
  user: UserEntity;
}

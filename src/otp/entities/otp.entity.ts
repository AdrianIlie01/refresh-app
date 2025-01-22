import {
  BaseEntity,
  Column,
  CreateDateColumn,
  Entity, JoinColumn,
  ManyToOne,
  PrimaryColumn, PrimaryGeneratedColumn,
  UpdateDateColumn
} from "typeorm";
import { UserEntity } from '../../user/entities/user.entity';
import { Action } from '../../shared/action';

@Entity('otp')
export class OtpEntity extends BaseEntity {

  @PrimaryGeneratedColumn( 'uuid')
  id: string;

  @Column({ type: 'enum', enum: Action })
  action: Action;

  @Column({ type: 'varchar', length: 6 })
  otp: string;

  @Column({ type: 'datetime' })
  expires_at: Date;

  @ManyToOne(() => UserEntity, (user: UserEntity) => user.otp, {eager: true})
  @JoinColumn({ name: 'user', referencedColumnName: 'id' })
  user: UserEntity;
}

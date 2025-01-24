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

@Entity('token_blacklist')
export class TokenBlackListEntity extends BaseEntity {

  @PrimaryGeneratedColumn( 'uuid')
  id: string;

  @Column({ type: 'varchar', length: 512  })
  token: string;

  @Column({ type: 'datetime' })
  expires_at: Date;

  @ManyToOne(() => UserEntity, (user: UserEntity) => user.expired_token, {eager: true})
  @JoinColumn({ name: 'user', referencedColumnName: 'id' })
  user: UserEntity;
}

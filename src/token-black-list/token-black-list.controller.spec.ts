import { Test, TestingModule } from '@nestjs/testing';
import { TokenBlackListController } from './token-black-list.controller';
import { TokenBlackListService } from './token-black-list.service';

describe('TokenBlackListController', () => {
  let controller: TokenBlackListController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [TokenBlackListController],
      providers: [TokenBlackListService],
    }).compile();

    controller = module.get<TokenBlackListController>(TokenBlackListController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
